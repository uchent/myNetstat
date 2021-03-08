#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <string.h>
#include <iomanip>
#include <dirent.h> /* opendir, readdir */
#include <unistd.h> /* readlink */
#include <getopt.h> /* getopt_long */
#include <arpa/inet.h>/* inet.* */
#include <regex>

using namespace::std;

string tcp_path = "/proc/net/tcp";
string tcp6_path = "/proc/net/tcp6";
string udp_path = "/proc/net/udp";
string udp6_path = "/proc/net/udp6";

struct clist{
    string proto;
    string local_addr;
    string foreign_addr;
    int PID;
    string P_name;
    string arguments;
}tcps[10000],udps[10000],tcp6s[10000],udp6s[10000];

static struct option opts[] = {
		{"tcp", 0, NULL, 't'},
		{"udp", 0, NULL, 'u'}
};

inline 
string getdec(string hexstr){
    return to_string(strtol(hexstr.c_str(), 0, 16));
}

string v4_HEXtoDEC(string hexip){
    string ret;
    for(int it =  0; it < hexip.length(); it+=2){
        if(hexip[it]==':'){
            ret += ':';
            break;
        }
        string stemp = hexip.substr(it, 2);
        if(it != 0){
            ret.insert(0, getdec(stemp)+'.');
        }
        else
        {
            ret.insert(0, getdec(stemp));
        }
    }
    string temp = getdec(hexip.substr(9, 4));
    ret += temp;
    return ret;

}

string v6_HEXtoDEC(string hexip){
    string ret;
    for(int i = 0; i<32; i+=8){
        ret += hexip.substr(i+6,2);
        ret += hexip.substr(i+4,2)+':';
        ret += hexip.substr(i+2,2);
        ret += hexip.substr(i,2)+':';
    }
    ret.pop_back(); //pop last ':'
    const char* c =ret.c_str();
    //cout << c << endl;
    struct sockaddr_in6 addr;
    char str[INET6_ADDRSTRLEN];

    inet_pton(AF_INET6, c, &addr.sin6_addr);
    inet_ntop(AF_INET6, &addr.sin6_addr, str, INET6_ADDRSTRLEN);
    ret.assign(str);

    ret += ':'+getdec(hexip.substr(33,4));

    return ret;
}

int main(int argc, char** argv){
    string tcp_lip[50];
    string tcp_rip[50];
    string tcp_inode[50];
    string tcp6_lip[50];
    string tcp6_rip[50];
    string tcp6_inode[50];
    string udp_lip[50];
    string udp_rip[50];
    string udp_inode[50];
    string udp6_lip[50];
    string udp6_rip[50];
    string udp6_inode[50];
    string skip;
    string filter;
    int tindex = 0;
    int t6index = 0; 
    int uindex = 0;
    int u6index = 0;
    int ac;
    bool T_flag = 0;
    bool U_flag = 0;

    while((ac = getopt_long(argc, argv, "tu", opts, NULL))!= -1){
		switch(ac){
			case 't':
                T_flag = 1;
				break;
			case 'u':
                U_flag = 1;
				break;
			case '?':
				cout<<"uknown option " << optopt << endl;
				break;
			default :
				break;
		}
	}
    if(!T_flag && !U_flag){
        T_flag = 1;
        U_flag = 1;
    }
    /*filter string*/
    if(optind < argc){
        //filter += ".";
        for(int i = optind; i < argc; i++){
			filter += argv[i];
            if((i+1)< argc)
                filter += ' ';
		}
        //filter += ".*";
        //cout << filter <<endl;
    }
    regex reg(filter,regex_constants::icase);
    
    /*get tcp ips & inodes*/
    int k = 0;
    ifstream tcpfile(tcp_path);
    getline(tcpfile, skip);
    while(tcpfile.peek()!=EOF){
        tcpfile>>skip;
        tcpfile>>tcp_lip[k];
        tcpfile>>tcp_rip[k];
        for(int i = 0; i<6; i++){
            tcpfile>>skip;
        }
        tcpfile>>tcp_inode[k];
        getline(tcpfile, skip);

        //cout<< tcp_lip[k] <<endl;
        //cout<< tcp_rip[k] <<endl;
        //cout<< tcp_inode[k] <<endl;
        k++;
    }
    tcpfile.close();
    k = 0;
    /*get tcp6 ips & inodes*/
    ifstream tcp6file(tcp6_path);
    getline(tcp6file, skip);
    while(tcp6file.peek()!=EOF){
        tcp6file>>skip;
        tcp6file>>tcp6_lip[k];
        tcp6file>>tcp6_rip[k];
        for(int i = 0; i<6; i++){
            tcp6file>>skip;
        }
        tcp6file>>tcp6_inode[k];
        getline(tcp6file, skip);
        
        //cout<< tcp6_lip[k] <<endl;
        //cout<< tcp6_rip[k] <<endl;
        //cout<< tcp6_inode[k] <<endl;
        k++;
    }
    tcp6file.close();
    k = 0;
    /*get udp ips & inodes*/
    ifstream udpfile(udp_path);
    getline(udpfile, skip);
    while(udpfile.peek()!=EOF){
        udpfile>>skip;
        udpfile>>udp_lip[k];
        udpfile>>udp_rip[k];
        for(int i = 0; i<6; i++){
            udpfile>>skip;
        }
        udpfile>>udp_inode[k];
        getline(udpfile, skip);
        
        //cout<< udp_lip[k] <<endl;
        //cout<< udp_rip[k] <<endl;
        //cout<< udp_inode[k] <<endl;
        k++;
    }
    udpfile.close();
    k = 0;
    /*get udp6 ips & inodes*/
    ifstream udp6file(udp6_path);
    getline(udp6file, skip);
    while(udp6file.peek()!=EOF){
        udp6file>>skip;
        udp6file>>udp6_lip[k];
        udp6file>>udp6_rip[k];
        for(int i = 0; i<6; i++){
            udp6file>>skip;
        }
        udp6file>>udp6_inode[k];
        getline(udp6file, skip);
        
        //cout<< udp6_lip[k] <<endl;
        //cout<< udp6_rip[k] <<endl;
        //cout<< udp6_inode[k] <<endl;
        k++;
    }
    udp6file.close();
    k = 0;

    /*read proc processes links*/
    for(int pid = 1; pid<=31368; pid++){
        string fd_path = "/proc/" + to_string(pid) + "/fd/";
        string comm_path = "/proc/" + to_string(pid) + "/comm";
        string cmdline_path = "/proc/" + to_string(pid) + "/cmdline";
        const char* path = fd_path.c_str();
        DIR* dirp = opendir(path);
            
        struct dirent *dire;
        if(dirp != nullptr){
            //cout<<i<<endl;
            while(dire = readdir(dirp)){
                if(strcmp(dire->d_name,".")!=0 && strcmp(dire->d_name,"..")!=0){
                    string file_path = fd_path + dire->d_name;
                    const char* link_path = file_path.c_str();
                    char buf[15];
                    //cout<<link_path << endl;
                    readlink(link_path, buf, sizeof(buf));//get symbolic link
                    string sbuf(buf);
                    
                    for(int k=0; k<50; k++){
                        /*TCP*/
                        size_t t_found = sbuf.find(tcp_inode[k]);
                        if(tcp_inode[k]!="" && tcp_inode[k].compare("0")!=0 && t_found != string::npos ){
                            ifstream comm(comm_path);
                            ifstream cmdl(cmdline_path);
                            string name;
                            string cmdline;
                            getline(comm, name);
                            getline(cmdl, cmdline);
                            tcps[tindex].proto = "tcp";
                            tcps[tindex].local_addr = v4_HEXtoDEC(tcp_lip[k]);
                            tcps[tindex].foreign_addr = v4_HEXtoDEC(tcp_rip[k]);
                            tcps[tindex].PID = pid;
                            tcps[tindex].P_name = name;
                            tcps[tindex].arguments = cmdline;
                            tindex++;
                            //cout<< "PID : " << pid << " name : "<< name<< " link->inode : "<< tcp_inode[k] << endl;
                        }
                        /*TCP6*/
                        size_t t6_found = sbuf.find(tcp6_inode[k]);
                        if(tcp6_inode[k]!="" && tcp6_inode[k].compare("0")!=0 && t6_found != string::npos ){
                            ifstream comm(comm_path);
                            ifstream cmdl(cmdline_path);
                            string name;
                            string cmdline;
                            getline(comm, name);
                            getline(cmdl, cmdline);
                            tcp6s[t6index].proto = "tcp6";
                            tcp6s[t6index].local_addr = v6_HEXtoDEC(tcp6_lip[k]);
                            tcp6s[t6index].foreign_addr = v6_HEXtoDEC(tcp6_rip[k]);
                            tcp6s[t6index].PID = pid;
                            tcp6s[t6index].P_name = name;
                            tcp6s[t6index].arguments = cmdline;
                            t6index++;
                            //cout<< "PID : " << pid << " name : "<< name<< " link->inode : "<< tcp6_inode[k] << endl;
                        }
                        /*UDP*/
                        size_t u_found = sbuf.find(udp_inode[k]);
                        if(udp_inode[k]!="" && udp_inode[k].compare("0")!=0 && u_found != string::npos ){
                            ifstream comm(comm_path);
                            ifstream cmdl(cmdline_path);
                            string name;
                            string cmdline;
                            getline(comm, name);
                            getline(cmdl, cmdline);
                            udps[uindex].proto = "udp";
                            udps[uindex].local_addr = v4_HEXtoDEC(udp_lip[k]);
                            udps[uindex].foreign_addr = v4_HEXtoDEC(udp_rip[k]);
                            udps[uindex].PID = pid;
                            udps[uindex].P_name = name;
                            udps[uindex].arguments = cmdline;
                            uindex++;
                            //cout<< "PID : " << pid << " name : "<< name<< " link->inode : "<< udp_inode[k] << endl;
                        }
                        /*UDP6*/
                        size_t u6_found = sbuf.find(udp6_inode[k]);
                        if(udp6_inode[k]!="" && udp6_inode[k].compare("0")!=0 && u6_found != string::npos ){
                            ifstream comm(comm_path);
                            ifstream cmdl(cmdline_path);
                            string name;
                            string cmdline;
                            getline(comm, name);
                            getline(cmdl, cmdline);
                            udp6s[u6index].proto = "udp6";
                            udp6s[u6index].local_addr = v6_HEXtoDEC(udp6_lip[k]);
                            udp6s[u6index].foreign_addr = v6_HEXtoDEC(udp6_rip[k]);
                            udp6s[u6index].PID = pid;
                            udp6s[u6index].P_name = name;
                            udp6s[u6index].arguments = cmdline;
                            u6index++;
                            //cout<< "PID : " << pid << " name : "<< name<< " link->inode : "<< udp6_inode[k] << endl;
                        }
                    }
                    
                }  
            }
        }
        closedir(dirp);
        
    }
    /*read proc processes links*/
    
    /*print*/
    if(T_flag){
        /*TCP*/
        cout<<"List of TCP connections :"<<endl;
        cout<< left << setw(10) <<"Proto" << setw(40) <<"Local Address"<< setw(40) <<"Foreign Address"<<"PID/Program and auguments"<<endl;
        for(int i =0; i<1000; i++){
            if(tcps[i].proto=="")
                break;
            else{
                string str = tcps[i].proto + tcps[i].local_addr + tcps[i].foreign_addr + to_string(tcps[i].PID) + tcps[i].P_name + tcps[i].arguments;
                if(regex_search(str, reg)){
                    cout<< setw(10) << tcps[i].proto << setw(40) << tcps[i].local_addr << setw(40) << tcps[i].foreign_addr
                    << tcps[i].PID << "/" << tcps[i].P_name << "  " << tcps[i].arguments << endl;
                }
            }
        }

        /*TCP6*/
        for(int i =0; i<1000; i++){
            if(tcp6s[i].proto=="")
                break;
            else{
                string str = tcp6s[i].proto + tcp6s[i].local_addr + tcp6s[i].foreign_addr + to_string(tcp6s[i].PID) + tcp6s[i].P_name + tcp6s[i].arguments;
                if(regex_search(str, reg)){
                    cout<< setw(10) << tcp6s[i].proto << setw(40) << tcp6s[i].local_addr << setw(40) << tcp6s[i].foreign_addr
                    << tcp6s[i].PID <<"/"<< tcp6s[i].P_name << "    " << tcp6s[i].arguments << endl;
                }
            }
        }
        cout<<endl;
    }
    
   
    if(U_flag){
        /*UDP*/
        cout<<"List of UDP connections :"<<endl;
        cout<< left << setw(10) <<"Proto" << setw(40) <<"Local Address"<< setw(40) <<"Foreign Address"<<"PID/Program and auguments"<<endl;

        for(int i =0; i<1000; i++){
            if(udps[i].proto=="")
                break;
            else{
                string str = udps[i].proto + udps[i].local_addr + udps[i].foreign_addr + to_string(udps[i].PID) + udps[i].P_name + udps[i].arguments;
                if(regex_search(str, reg)){
                    cout<< setw(10) << udps[i].proto << setw(40) << udps[i].local_addr << setw(40) << udps[i].foreign_addr
                    << udps[i].PID << "/" << udps[i].P_name << "    " << udps[i].arguments << endl;
                }
            }
        }

        /*UDP6*/
        for(int i =0; i<1000; i++){
            if(udp6s[i].proto=="")
                break;
            else{
                string str = udp6s[i].proto + udp6s[i].local_addr + udp6s[i].foreign_addr + to_string(udp6s[i].PID) + udp6s[i].P_name + udp6s[i].arguments;
                if(regex_search(str, reg)){
                    cout<< setw(10) << udp6s[i].proto << setw(40) << udp6s[i].local_addr << setw(40) << udp6s[i].foreign_addr
                    << udp6s[i].PID << "/" << udp6s[i].P_name << "    " << udp6s[i].arguments << endl;
                }
            }
        }
    }
    
    
    
    
    return 0;
}