from pathlib import Path
import subprocess
import tempfile
import unittest


class RulesetExportTest(unittest.TestCase):
    def test_url_regex_is_not_an_inline_comment(self):
        root = Path(__file__).resolve().parents[1]
        source = (root/'src/handler/interfaces.cpp').read_text()
        start = source.index('while (getline(ss, strLine, delimiter)) {')
        block = source[start + len('while (getline(ss, strLine, delimiter)) {'):source.index('switch (type_int)', start)]
        cpp = r'''
#include <string>
#include <cassert>
using namespace std;
bool strFind(const string&s,const string&t){return s.find(t)!=string::npos;}
bool startsWith(const string&s,const string&t){return s.rfind(t,0)==0;}
string trimWhitespace(const string&s){auto b=s.find_first_not_of(" \t\r\n");return b==string::npos?"":s.substr(b,s.find_last_not_of(" \t\r\n")-b+1);}
string emit(string strLine){for(int once=0;once<1;++once){
''' + block + r'''
return strLine;}return "";}
int main(){
 assert(emit("URL-REGEX,^https://example.com/path")=="URL-REGEX,^https://example.com/path");
 assert(emit("// comment").empty());
 assert(emit("DOMAIN-SUFFIX,example.com")=="DOMAIN-SUFFIX,example.com");
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p/'test.cpp').write_text(cpp)
            subprocess.run(['c++', '-std=c++17', str(p/'test.cpp'), '-o', str(p/'test')], check=True)
            subprocess.run([str(p/'test')], check=True)


if __name__ == '__main__': unittest.main()
