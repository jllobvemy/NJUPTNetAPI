#pragma once
#include <string>

class auto_login
{
public:
	enum class operators { cmcc, china_net, campus };
	enum class login_status { succeed, failed, repeat_login};
	auto_login(std::string _username, std::string _passwd, operators _operator, std::string _ip = auto_login::get_ip());
	login_status login();
	bool status;
	std::string username;
	std::string passwd;
	operators opt;
private:
	static std::string get_ip();
	void check_status();
	std::string ip_;
};

std::ostream& operator<<(std::ostream& out, auto_login::login_status s);

