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
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <deque>

#include "nlohmann/json.hpp"

#include "AbiDecoder.h"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace base64 = beast::detail::base64;
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

using namespace nlohmann;

//------------------------------------------------------------------------------

// Report a failure
void
fail(beast::error_code ec, char const* what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

std::string http_get(const char* host, const char* port, const char *target)
{
    try
    {
        // The io_context is required for all I/O
        net::io_context ioc;

        // The SSL context is required, and holds certificates
        ssl::context ctx{ ssl::context::tlsv12_client };
        // Verify the remote server's certificate
        //ctx.set_verify_mode(ssl::verify_peer);

        // These objects perform our I/O
        tcp::resolver resolver(ioc);
        beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if (!SSL_set_tlsext_host_name(stream.native_handle(), host))
        {
            beast::error_code ec{ static_cast<int>(::ERR_get_error()), net::error::get_ssl_category() };
            throw beast::system_error{ ec };
        }

        // Look up the domain name
        auto const results = resolver.resolve(host, port);

        // Make the connection on the IP address we get from a lookup
        beast::get_lowest_layer(stream).connect(results);

        // Perform the SSL handshake
        stream.handshake(ssl::stream_base::client);

        // Set up an HTTP GET request message
        http::request<http::string_body> req{ http::verb::get, target, 11 };
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        // Send the HTTP request to the remote host
        http::write(stream, req);

        // This buffer is used for reading and must be persisted
        beast::flat_buffer buffer;

        // Declare a container to hold the response
        http::response<http::dynamic_body> res;

        // Receive the HTTP response
        http::read(stream, buffer, res);

        // Gracefully close the stream
        beast::error_code ec;
        stream.shutdown(ec);

        return beast::buffers_to_string(res.body().cdata());
    }
    catch (std::exception const& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return std::string();
    }
}

class wss_provider_session : public std::enable_shared_from_this<wss_provider_session>
{
    net::io_context& ioc;
    ssl::context& ctx;

    using subscription_callback = std::function<void(const std::string&)>;
    using rpc_callback = std::function<void(const json&)>;

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

    AbiDecoder decoder_;

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

        init_decoder();

        // Subscribe
        async_subscribe_pending([](const json&) {}, [this](const std::string &hash) { on_subscription(hash); });

        do_idle();
    }

    void init_decoder()
    {
        auto abi = http_get("api.polygonscan.com", "443",
            "/api?module=contract&action=getabi&address=0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff&format=raw");

        auto abi_json = json::parse(abi);
        decoder_.addABI(abi_json);
    }

    void on_subscription(const std::string &hash)
    {
        //std::cout << hash << std::endl;

        async_get_transaction(hash, [this](const json& j) { on_get_transaction(j); });
    }

    void on_get_transaction(const json& j)
    {
        //std::cout << j.dump(2) << std::endl;

        if (j.empty() || j.is_null())
            return;

        auto input = j["input"].get<std::string>();
        auto decoded = decoder_.decodeMethod(input);

        if (!decoded.empty())
            std::cout << decoded.dump(2) << std::endl;
    }

    void async_subscribe_pending(rpc_callback callback, subscription_callback on_subscription)
    {
        on_subscription_ = on_subscription;
        rpc_call("eth_subscribe", { "newPendingTransactions" }, callback);
    }

    void async_get_transaction(const std::string& hash, rpc_callback callback)
    {
        rpc_call("eth_getTransactionByHash", { hash }, callback);
    }

    void rpc_call(const std::string& method, const json::array_t& params, rpc_callback callback)
    {
        json j1{
            { "id", next_id_ },
            { "method", method },
            { "params", params },
        };

        send(j1.dump());

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
        auto j = json::parse(msg);

        auto j_id = j.find("id");
        if (j_id != j.end()) {
            auto id = j_id.value().get<int>();

            auto j_result = j.find("result");
            if (j_result != j.end())
                rpc_reqs_[id].callback(j_result.value());

            rpc_reqs_.erase(id);
        }
        else {
            auto j_method = j.find("method");
            if (j_method == j.end())
                return;

            auto method = j_method.value().get<std::string>();
            if (method == "eth_subscription") {
                on_subscription_(j.at("params").at("result").get<std::string>());
            }
        }
    }

    void on_close(beast::error_code ec)
    {
        if (ec)
            return fail(ec, "close");

        // If we get here then the connection is closed gracefully
    }

public:
    // Resolver and socket require an io_context
    explicit wss_provider_session(net::io_context& ioc, ssl::context& ctx)
        : ioc(ioc), ctx(ctx)
        , resolver_(net::make_strand(ioc))
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
    std::make_shared<wss_provider_session>(ioc, ctx)->run(host, port);

    // Run the I/O service. The call will return when
    // the socket is closed.
    ioc.run();

    return EXIT_SUCCESS;
}
