#ifndef __HTTP_CLIENT_H__
#define __HTTP_CLIENT_H__

#include <string>

std::string http_get(const char* host, const char* port, const char* target);

#endif
