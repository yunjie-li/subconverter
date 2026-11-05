"""Compile the real Loon VLESS branch with synthetic nodes (no network/dependencies)."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LoonExportTest(unittest.TestCase):
    def test_tcp_ws_reality_and_timeout(self):
        source = (ROOT / 'src/generator/config/subexport.cpp').read_text()
        loon = source[source.index('proxyToLoon('):source.index('static std::string formatSingBoxInterval')]
        branch = loon[loon.index('            case ProxyType::VLESS:'):loon.index('            case ProxyType::ShadowsocksR:')]
        expressions = re.findall(r'group \+= ",max-timeout=" \+ (.*);', loon)
        self.assertEqual(len(expressions), 2)
        cpp = r'''
#include <string>
#include <cassert>
using namespace std;
constexpr unsigned long long hash_bytes(const char* s,size_t n){unsigned long long h=0;for(size_t i=0;i<n;++i)h=h*131+static_cast<unsigned char>(s[i]);return h;}
constexpr unsigned long long operator""_hash(const char*s,size_t n){return hash_bytes(s,n);}
auto hash_(const string&s){return hash_bytes(s.data(),s.size());}
enum class ProxyType {VLESS};
struct Tri {bool get()const{return true;}bool is_undef()const{return false;}};
struct Proxy {ProxyType Type=ProxyType::VLESS;string Fingerprint;};
string emit(string transproto,string flow="",string pk="",string shortId="",string fp="",bool tlssecure=true){
 Proxy x;x.Fingerprint=fp;string hostname="example.com",port="443",id="11111111-1111-4111-8111-111111111111",path="/ws",host="cdn.example.com",sni="tls.example.com";Tri udp,scv;string proxy;
 for(int i=0;i<1;++i){switch(x.Type){
''' + branch + '\n}return proxy;}return "";}\n'
        for i, expr in enumerate(expressions):
            cpp += 'string timeout' + str(i) + '(long value){struct{long Timeout;}x{value};return ' + expr + ';}\n'
        cpp += r'''
int main(){
 assert(emit("tcp").find("transport=tcp")!=string::npos);
 assert(emit("tcp").find("over-tls=true")!=string::npos);
 assert(emit("tcp").find("sni=tls.example.com")!=string::npos);
 assert(emit("ws").find("path=/ws,host=cdn.example.com")!=string::npos);
 auto reality=emit("tcp","xtls-rprx-vision","public-key","1234","chrome");
 assert(reality.find("public-key=\"public-key\"")!=string::npos);
 assert(reality.find("short-id=1234")!=string::npos);
 assert(reality.find("tls-profile=chrome")!=string::npos);
 assert(emit("tcp","","","","safari").find("tls-profile=safari-ios18")!=string::npos);
 assert(emit("grpc").empty());assert(emit("tcp","unsupported").empty());
 assert(emit("ws","xtls-rprx-vision").empty());
 assert(emit("tcp","","","","",false).find("over-tls=false")!=string::npos);
 assert(timeout0(5)=="5000");assert(timeout1(5)=="5000");
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / 'test.cpp').write_text(cpp)
            subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-Wall', '-Wextra', '-Werror', str(p/'test.cpp'), '-o', str(p/'test')], check=True)
            subprocess.run([str(p/'test')], check=True)


if __name__ == '__main__':
    unittest.main()
