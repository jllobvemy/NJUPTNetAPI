#include "auto_login.hpp"
#include <iostream>
int main(int argv, char* args)
{
	auto_login a("BXXXXXXXX", "XXXXXX", auto_login::operators::china_net);
	std::cout << "current status: " << a.status << std::endl;
	std::cout << "LOGINING..." << std::endl;
	auto res = a.login();
	std::cout << "login infomation: " << res << std::endl;
	std::cout << "current status: " << a.status << std::endl;
}