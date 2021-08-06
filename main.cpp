#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <deque>
#include "nlohmann/json.hpp"
#include "secp256k1/include/secp256k1_recovery.h"
#include "Keccak.h"

#include "http_client.h"
#include "AbiDecoder.h"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace base64 = beast::detail::base64;
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
using namespace boost::multiprecision;

using namespace nlohmann;

//------------------------------------------------------------------------------

// Report a failure
void
fail(beast::error_code ec, char const* what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

class wss_provider_session : public std::enable_shared_from_this<wss_provider_session>
{
public:
    using subscription_callback = std::function<void(const std::string&)>;
    using rpc_callback = std::function<void(const json&, const json&)>;

protected:
    virtual void on_initialized() { }
    virtual void on_closed() { }

    tcp::resolver resolver_;
    websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws_;
    beast::flat_buffer buffer_;
    std::string host_;
    std::string credentials_;

    std::deque<std::string> pending_msgs_;

    uint32_t next_id_ = 1;

    subscription_callback on_subscription_;

    struct RpcRequest {
        uint32_t id;
        rpc_callback callback;
    };

    std::map<int, RpcRequest> rpc_reqs_;

    void on_resolve(beast::error_code ec, tcp::resolver::results_type results)
    {
        if (ec)
            return fail(ec, "resolve");

        // Set a timeout on the operation
        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

        // Make the connection on the IP address we get from a lookup
        beast::get_lowest_layer(ws_).async_connect(
            results,
            beast::bind_front_handler(
                &wss_provider_session::on_connect,
                shared_from_this()));
    }

    void on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type ep)
    {
        if (ec)
            return fail(ec, "connect");

        // Update the host_ string. This will provide the value of the
        // Host HTTP header during the WebSocket handshake.
        // See https://tools.ietf.org/html/rfc7230#section-5.4
        host_ += ':' + std::to_string(ep.port());

        // Set a timeout on the operation
        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if (!SSL_set_tlsext_host_name(
            ws_.next_layer().native_handle(),
            host_.c_str()))
        {
            ec = beast::error_code(static_cast<int>(::ERR_get_error()),
                net::error::get_ssl_category());
            return fail(ec, "connect");
        }

        // Perform the SSL handshake
        ws_.next_layer().async_handshake(
            ssl::stream_base::client,
            beast::bind_front_handler(
                &wss_provider_session::on_ssl_handshake,
                shared_from_this()));
    }

    void on_ssl_handshake(beast::error_code ec)
    {
        if (ec)
            return fail(ec, "ssl_handshake");

        // Turn off the timeout on the tcp_stream, because
        // the websocket stream has its own timeout system.
        beast::get_lowest_layer(ws_).expires_never();

        // Set suggested timeout settings for the websocket
        ws_.set_option(
            websocket::stream_base::timeout::suggested(
                beast::role_type::client));

        // Set a decorator to change the User-Agent of the handshake
        ws_.set_option(websocket::stream_base::decorator(
            [this](websocket::request_type& req)
            {
                req.set(http::field::user_agent,
                    std::string(BOOST_BEAST_VERSION_STRING) +
                    " websocket-client-async-ssl");

                if (!credentials_.empty()) {
                    std::string credentials;
                    credentials.resize(base64::encoded_size(credentials_.length()));
                    credentials.resize(base64::encode(&credentials[0], credentials_.c_str(), credentials_.length()));

                    req.set(http::field::authorization,
                        std::string("Basic ") + credentials);
                }
            }));

        // Perform the websocket handshake
        ws_.async_handshake(host_, "/",
            beast::bind_front_handler(
                &wss_provider_session::on_handshake,
                shared_from_this()));
    }

    void on_handshake(beast::error_code ec)
    {
        if (ec)
            return fail(ec, "handshake");

        on_initialized();

        do_idle();
    }

    void async_subscribe_pending(rpc_callback callback, subscription_callback on_subscription)
    {
        on_subscription_ = on_subscription;
        rpc_call("eth_subscribe", { "newPendingTransactions" }, callback);
    }

    void rpc_call(const std::string& method, const json::array_t& params, rpc_callback callback)
    {
        json msg{
            { "id", next_id_ },
            { "method", method },
            { "params", params },
        };

        send(msg.dump());

        RpcRequest req = { next_id_, callback };
        rpc_reqs_[next_id_] = req;

        ++next_id_;
        if (next_id_ == 0)
            ++next_id_;
    }

    void send(const std::string msg)
    {
        pending_msgs_.push_back(msg);
    }

    void do_idle()
    {
        if (!do_write()) {
            do_read();
        }
    }

    bool do_write()
    {
        if (pending_msgs_.empty())
            return false;

        auto msg = pending_msgs_.front();

        pending_msgs_.pop_front();

        ws_.async_write(
            net::buffer(msg),
            beast::bind_front_handler(
                &wss_provider_session::on_write,
                shared_from_this()));
        return true;
    }

    void on_write(beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if (ec)
            return fail(ec, "write");

        do_read();
    }

    void do_read()
    {
        // Read a message into our buffer
        buffer_.clear();
        ws_.async_read(
            buffer_,
            beast::bind_front_handler(
                &wss_provider_session::on_read,
                shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if (ec)
            return fail(ec, "read");

        auto r = beast::buffers_to_string(buffer_.data());

        on_message(r);

        do_idle();
    }

    void on_message(const std::string &msg)
    {
        auto rpc_res = json::parse(msg);

        auto id_it = rpc_res.find("id");
        if (id_it != rpc_res.end()) {
            auto id = id_it.value().get<int>();

            rpc_reqs_[id].callback(rpc_res["result"], rpc_res["error"]);

            rpc_reqs_.erase(id);
        }
        else {
            auto method_it = rpc_res.find("method");
            if (method_it == rpc_res.end())
                return;

            auto method = method_it.value().get<std::string>();
            if (method == "eth_subscription") {
                on_subscription_(rpc_res.at("params").at("result").get<std::string>());
            }
        }
    }

    void on_close(beast::error_code ec)
    {
        on_closed();

        if (ec)
            return fail(ec, "close");

        // If we get here then the connection is closed gracefully
    }

public:
    // Resolver and socket require an io_context
    explicit wss_provider_session(net::io_context& ioc, ssl::context& ctx)
        : resolver_(net::make_strand(ioc))
        , ws_(net::make_strand(ioc), ctx)
    {
    }

    // Start the asynchronous operation
    void run(const std::string &host, const std::string &port)
    {
        auto credentials_pos = host.find('@');

        // Save these for later
        if (credentials_pos == std::string::npos) {
            host_ = host;
        }
        else {
            host_ = host.substr(credentials_pos + 1);
            credentials_ = host.substr(0, credentials_pos);
        }

        // Look up the domain name
        resolver_.async_resolve(
            host_,
            port,
            beast::bind_front_handler(
                &wss_provider_session::on_resolve,
                shared_from_this()));
    }
};

static std::string to_hexstring(const uint8_t *data, size_t size)
{
    std::string s;
    boost::algorithm::hex_lower(data, data+size, std::back_inserter(s));
    return s.insert(0, "0x");
}

static std::string to_hexstring(const std::vector<uint8_t>& bytes)
{
    std::string s;
    boost::algorithm::hex_lower(bytes.begin(), bytes.end(), std::back_inserter(s));
    return s.insert(0, "0x");
}

static std::string to_hexstring(size_t value, bool leading_zero = false)
{
    std::ostringstream ss;
    ss << std::hex << value;
    auto s = ss.str();
    if (leading_zero && (s.length() % 2))
        s.insert(0, "0");
    return s.insert(0, "0x");
}

static std::string& remove_hexspec(std::string& s)
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s.erase(0, 2);
    return s;
}

static std::vector<uint8_t> arrayify(const std::string& value)
{
    auto hex = value;
    remove_hexspec(hex);

    if (hex.length() % 2)
        hex.insert(0, "0");

    std::vector<uint8_t> arr(hex.length() >> 1);
    for (size_t i = 0; i < hex.length(); i += 2)
        arr[i >> 1] = (uint8_t)std::stoul(hex.substr(i, 2), nullptr, 16);
    return arr;
}

static std::vector<uint8_t> arrayify(uint64_t value)
{
    return arrayify(to_hexstring(value));
}

static const char* privkey = "0x733e114e7e9bd9e63afaed959001c95d6909cd23736b32e8b05f68a0a5d76dac";
static const char* wallet_address = "0xf942BF34eE2aca7a5017190eCa83C50171b0122B";

class my_session : public wss_provider_session
{
    AbiDecoder decoder_;
    secp256k1_context* secp256k1_ctx_;

    unsigned int chain_id_ = 0;
    unsigned int next_nonce_ = 0;

    bool wallet_initialized_ = false;

    void on_initialized()
    {
        init_decoder();

        secp256k1_ctx_ = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

        // Subscribe
        async_subscribe_pending([](const json&, const json&) {}, [this](const std::string& hash) { on_subscription(hash); });
    }

    void on_closed()
    {
        secp256k1_context_destroy(secp256k1_ctx_);
    }

    void init_decoder()
    {
        auto abi = http_get("api.polygonscan.com", "443",
            "/api?module=contract&action=getabi&address=0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff&format=raw");

        auto abi_json = json::parse(abi);
        decoder_.addABI(abi_json);

        init_swap();

        test_swap();
    }

    void init_swap()
    {
        async_get_chain_id([=](const json& r, const json& e) {
            chain_id_ = std::stoul(r.get<std::string>(), nullptr, 16);
            std::cout << "chain_id: " << chain_id_ << std::endl;

            async_get_transaction_count(wallet_address, "pending", [=](const json& r, const json& e) {
                next_nonce_ = std::stoul(r.get<std::string>(), nullptr, 16);
                std::cout << "nonce: " << next_nonce_ << std::endl;

                wallet_initialized_ = true;

                on_init_wallet();
                });
            });
    }

    void on_init_wallet()
    {
        test_swap(); // NOTE: if you don't want to swap on initialization, remove this.
    }


    void test_swap()
    {
        if (!wallet_initialized_)
            return;

        static const char* contract = "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff";
        static const char* token_a = "0x2791bca1f2de4661ed88a30c99a7a9449aa84174";
        static const char* token_b = "0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6";

        auto start_time = std::chrono::system_clock::now();

        async_contract_method_call(
            chain_id_,
            contract,
            wallet_address, privkey,

            "swapExactTokensForTokens",
            {
                { "amountIn", 10000 },
                { "amountOutMin", 0 },
                { "path", { token_a, token_b } },
                { "to", wallet_address },
                { "deadline", 4255969257 },
            },
            {
                { "gasLimit", to_hexstring(250000) },
                { "gasPrice", to_hexstring(1010000000ul) }, // 1.01 gwei
            },

            [=](const json& r, const json& e) {
                if (!e.is_null()) {
                    std::cout << e.dump(2) << std::endl;
                    return;
                }

                auto duration = std::chrono::system_clock::now() - start_time;
                std::cout << "test_swap elapsed: "
                    << std::chrono::duration_cast<std::chrono::milliseconds>(duration).count()
                    << " msecs" << std::endl;

                std::cout << "tx hash: " << r.get<std::string>() << std::endl;
            }
        );
    }

    void async_contract_method_call(unsigned int chain_id, const std::string &contract, const std::string &address, const std::string &privkey, const std::string &method, const json &method_args, const json &overrides, rpc_callback callback)
    {
        // 1. encode data
        auto data = decoder_.encodeMethod(method, method_args);
        std::cout << "method: " << method << ", encoded data : " << data << std::endl;

        // 2. make tx
        json tx{
            { "data", data },
            { "nonce", to_hexstring(next_nonce_) },
            { "to", contract },
        };
        tx.update(overrides);

        std::cout << "tx:" << std::endl
            << tx.dump(2) << std::endl;

        // 3. tx RLP encode
        std::vector<uint8_t> tx_data_unsigned;
        serialize_tx(tx_data_unsigned, tx, to_hexstring(chain_id), "", "");
        std::cout << "tx_rlp: " << to_hexstring(tx_data_unsigned) << std::endl;

        // 4. tx digest
        Keccak keccak(256);
        keccak.update(tx_data_unsigned.data(), tx_data_unsigned.size());
        auto tx_data_unsigned_hash = keccak.finalize();
        std::cout << "tx_digest: " << to_hexstring(tx_data_unsigned_hash) << std::endl;

        // 5. sign tx digest
        secp256k1_ecdsa_recoverable_signature sig;
        secp256k1_ecdsa_sign_recoverable(secp256k1_ctx_, &sig, tx_data_unsigned_hash.data(), arrayify(privkey).data(), nullptr, nullptr);

        uint8_t sigdata[64];
        int recid;
        secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_ctx_, sigdata, &recid, &sig);
        std::string sig_r = to_hexstring(sigdata, 32);
        std::string sig_s = to_hexstring(sigdata+32, 32);

        std::cout << "sig: " << std::endl
            << "v:" << recid << std::endl
            << "r:" << sig_r << std::endl
            << "s:" << sig_s << std::endl
            ;

        // 6. re-encode tx with signature
        std::vector<uint8_t> tx_data_signed;
        serialize_tx(tx_data_signed, tx, to_hexstring(27 + (unsigned)recid + chain_id * 2 + 8), sig_r, sig_s);
        auto tx_signed = to_hexstring(tx_data_signed);
        std::cout << "signed_tx: " << tx_signed << std::endl;

        // 7. send to rpc
        async_send_raw_transaction(tx_signed, callback);
    }

    static void serialize_tx(std::vector<uint8_t>& payload, const json& tx, const std::string& v, const std::string& r, const std::string& s)
    {
        static const char* transactionFields[] = {
            "nonce", "gasPrice", "gasLimit", "to", "value", "data", nullptr,
        };

        for (const char** p = transactionFields; *p; p++) {
            auto name = *p;
            auto kv = tx.find(name);
            auto value_str = kv == tx.end() ? "" : kv.value().get<std::string>();
            auto data = encode(value_str);
            std::copy(data.begin(), data.end(), std::back_inserter(payload));
        }

        auto v_data = encode(v);
        std::copy(v_data.begin(), v_data.end(), std::back_inserter(payload));
        auto r_data = encode(r);
        std::copy(r_data.begin(), r_data.end(), std::back_inserter(payload));
        auto s_data = encode(s);
        std::copy(s_data.begin(), s_data.end(), std::back_inserter(payload));

        if (payload.size() <= 55) {
            payload.insert(payload.begin(), (uint8_t)(0xc0 + payload.size()));
        }
        else {
            auto length = arrayify(payload.size());
            length.insert(length.begin(), (uint8_t)(0xf7 + length.size()));
            payload.insert(payload.begin(), length.begin(), length.end());
        }
    }

    static std::vector<uint8_t> encode(const std::string& value)
    {
        auto data = arrayify(value);

        if (data.size() == 1 && data[0] <= 0x7f)
            return data;
        else if (data.size() <= 55) {
            data.insert(data.begin(), (uint8_t)(0x80 + data.size()));
            return data;
        }
        else {
            auto length = arrayify(data.size());
            length.insert(length.begin(), (uint8_t)(0xb7 + length.size()));
            data.insert(data.begin(), length.begin(), length.end());
            return data;
        }
    }

    void on_subscription(const std::string& hash)
    {
        std::cout << hash << std::endl;

        async_get_transaction(hash, [this](const json& r, const json &e) { on_get_transaction(r); });
    }

    void on_get_transaction(const json& tx)
    {
        std::cout << tx.dump(2) << std::endl;

        if (tx.empty() || tx.is_null())
            return;

        auto input = tx["input"].get<std::string>();
        auto decoded = decoder_.decodeMethod(input);

        if (!decoded.empty()) {
            //test_swap();

            std::cout << input << std::endl;
            std::cout << decoded.dump(2) << std::endl;

            // NOTE: if you want to convert address or uint256/int256 type values
            // into number, do following:
            //uint256_t address{ decoded["params"]["to"].get<std::string>() };

            auto encoded = decoder_.encodeMethod(decoded["name"].get<std::string>(), decoded["params"]);
            std::cout << encoded << std::endl;

            if (input != encoded) {
                std::cout << "Error" << std::endl;
            }
        }
    }

    // RPC interfaces

    void async_get_chain_id(rpc_callback callback)
    {
        rpc_call("eth_chainId", json::array(), callback);
    }

    void async_get_transaction(const std::string& hash, rpc_callback callback)
    {
        rpc_call("eth_getTransactionByHash", { boost::algorithm::to_lower_copy(hash) }, callback);
    }

    void async_get_transaction_count(const std::string& address, const std::string &block_tag, rpc_callback callback)
    {
        rpc_call("eth_getTransactionCount", { boost::algorithm::to_lower_copy(address), block_tag }, callback);
    }

    void async_send_raw_transaction(const std::string& signed_tx, rpc_callback callback)
    {
        rpc_call("eth_sendRawTransaction", { signed_tx }, [=](const json& r, const json& e) {
            if (e.is_null())
                ++next_nonce_;
            callback(r, e);
            });
    }

public:
    explicit my_session(net::io_context& ioc, ssl::context& ctx)
        : wss_provider_session(ioc, ctx), secp256k1_ctx_(nullptr)
    {
    }
};

//------------------------------------------------------------------------------

int main(int argc, char** argv)
{
    std::string host = (argc > 1) ? argv[1] : "ws-matic-mainnet.chainstacklabs.com";
    std::string port = (argc > 2) ? argv[2] : "443";

    // The io_context is required for all I/O
    net::io_context ioc;

    // The SSL context is required, and holds certificates
    ssl::context ctx{ ssl::context::tlsv12_client };

    // Launch the asynchronous operation
    std::make_shared<my_session>(ioc, ctx)->run(host, port);

    // Run the I/O service. The call will return when
    // the socket is closed.
    ioc.run();

    return EXIT_SUCCESS;
}
