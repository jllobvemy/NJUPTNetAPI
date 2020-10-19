# NJUPTNetAPI
南京邮电大学校园网登录 C++ API
直接使用较为底层的WIN32 API 不适用于LINUX
未使用任何第三方库
轻量、快捷

# Example:
```C++
#include "auto_login.hpp"
#include <iostream>
int main()
{
	auto_login a("BXXXXXXXX", "XXXXXX", auto_login::operators::china_net);
	std::cout << "current status: " << a.status << std::endl;
	std::cout << "LOGINING..." << std::endl;
	auto res = a.login();
	std::cout << "login infomation: " << res << std::endl;
	std::cout << "current status: " << a.status << std::endl;
}
```

OutPut Example:
```Shell
current status: 1
LOGINING...
login infomation: repeat login
current status: 1
```
# 说明：
1. `auto_login`构造方法参数:
 - 校园网账号
 - 校园网密码
 - 运营商
 - 登录IP（默认自动获取）
2. `auto_login::operators`枚举出三种登录方式，分别为
 - `auto_login::operators::cmcc`
 - `auto_login::operators::china_net`
 - `auto_login::operators::campus`
 分别代表中国移动、中国电信、校园网
 
