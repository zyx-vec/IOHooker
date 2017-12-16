#include "plfs.h"

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>

#include <string>
#include <map>
#include <set>
#include <vector>
#include <list>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>

#define MAP(func, ret) \
    if (!(__real_ ## func)) { \
        __real_ ## func = (ret) dlsym(RTLD_NEXT, #func); \
        if (!(__real_ ## func)) std::cerr  << "Failed to link symbol: " << #func << std::endl; \
    }


struct plfs_file_t {
	Plfs_fd *fd;
	std::string *path;
    int flags;
    FILE* tmp_file;
	plfs_file_t(): fd(NULL), path(NULL), flags(0) {}
};
typedef plfs_file_t plfs_file;
std::map<int, plfs_file*> plfs_files;

std::vector<std::string> mount_points;
std::map<std::string, std::string> phys_paths;


struct plfs_dir_t {
    std::string* path;
    std::set<std::string>* files;
    std::set<std::string>::iterator iter;
    int dirFd;
    plfs_dir_t(): path(NULL), files(NULL), iter(NULL), dirFd(0) {}
};
typedef plfs_dir_t plfs_dir;
std::map<DIR*, plfs_dir*> opendirs;
std::map<int, DIR*> fd2dir;


int (*__real_open)(const char* path, int flags, ...) = NULL;
int (*__real_open64)(const char* path, int flags, ...) = NULL;
int (*__real_close)(int fd) = NULL;
ssize_t (*__real_write)(int fd, const void* buf, size_t count) = NULL;
ssize_t (*__real_read)(int fd, void* buf, size_t count) = NULL;

ssize_t (*__real_pread)(int fd, void* buf, size_t count, off_t pread) = NULL;
ssize_t (*__real_pwrite)(int fd, const void* buf, size_t count, off_t offset) = NULL;

ssize_t (*__real_pread64)(int fd, void *buf, size_t count, off64_t offset) = NULL;
ssize_t (*__real_pwrite64)(int fd, const void *buf, size_t count, off64_t offset) = NULL;

FILE* (*__real_tmpfile)(void) = NULL;
char* (*__real_get_current_dir_name)(void) = NULL;

FILE* (*__real_fopen)(const char* pathname, const char* mode) = NULL;
size_t (*__real_fread)(void* ptr, size_t size, size_t nmemb, FILE* stream) = NULL;
size_t (*__real_fwrite)(const void* ptr, size_t size, size_t nmemb, FILE* stream) = NULL;


int (*__real_fclose)(FILE* stream) = NULL;

int (*__real_chmod)(const char* pathname, mode_t mode) = NULL;


int (*__real_fgetc)(FILE* stream) = NULL;
int (*__real_getc)(FILE* stream) = NULL;

char* (*__real_fgets)(char* str, int count, FILE* stream) = NULL;

int (*__real_fputc)(int ch, FILE* stream) = NULL;
int (*__real_putc)(int ch, FILE* stream) = NULL;

int (*__real_fputs)(const char* str, FILE* stream) = NULL;
int (*__real_puts)(const char* str) = NULL;

int (*__real_printf)(const char* format, ...) = NULL;
int (*__real_vfprintf)(FILE *stream, const char *format, va_list ap) = NULL;
int (*__real_fprintf)(FILE* stream, const char* format, ...) = NULL;
int (*__real_vprintf)(const char *format, va_list ap) = NULL;

int (*__real_mkdir)(const char* pathname, mode_t mode) = NULL;
int (*__real_rmdir)(const char* pathname) = NULL;


DIR* (*__real_opendir)(const char* pathname) = NULL;
struct dirent* (*__real_readdir)(DIR* dir) = NULL;
int (*__real_closedir)(DIR* dir) = NULL;

int (*__real_chdir)(const char* pathname) = NULL;
char* (*__real_getcwd)(char* buf, size_t size) = NULL;

int (*__real_fcntl)(int fildes, int cmd, ...) = NULL;



int (*__real_rename)(const char* frompath, const char* topath) = NULL;


int (*__real_fflush)(FILE* stream) = NULL;


int (*__real_unlink)(const char* pathname) = NULL;


int (*__real_stat)(const char* pathname, struct stat* statbuf);
int (*__real___lxstat)(int vers, const char* path, struct stat* statbuf);

int (*__real___xstat)(int vers, const char *path, struct stat *buf);
int (*__real___fxstat)(int vers, int fd, struct stat *buf);

plfs_error_t plfs_logical_to_physical(const char *path, std::string& phys_path) {
    char* phys_path_ptr = NULL;
    
    plfs_error_t ret = plfs_expand_path(path, &phys_path_ptr, NULL, NULL);
    if(ret == PLFS_SUCCESS) {
        phys_path = phys_path_ptr;
        free(phys_path_ptr);
    }

    return ret;
}

void loadMounts() {
	MAP(open, int (*)(const char*, int, ...));
	MAP(read, ssize_t (*)(int, void*, size_t));
	MAP(close,int (*)(int));
	
	std::vector<std::string> possible_files;
	if (getenv("PLFSRC")) {
		std::string env_file = getenv("PLFSRC");
		possible_files.push_back(env_file);
	}
	if (getenv("HOME")) {
		std::string home_file = getenv("HOME");
		home_file.append("/.plfsrc");
		possible_files.push_back(home_file);
	}
	possible_files.push_back("/etc/plfsrc");
	
	for (std::vector<std::string>::iterator itr = possible_files.begin(); itr != possible_files.end(); itr++) {
		std::string contents;
		char buf[1024];

		int fd = __real_open(itr->c_str(), O_RDONLY);
		
		if (fd < 0) continue;
		
		int bytes = 0;
		while ((bytes = __real_read(fd, buf, 1024)) > 0) {
			contents.append(buf, bytes);
		}
		
		__real_close(fd);
		
		std::stringstream ss (contents);
		
		std::string mp ("mount_point:");
		std::string whitespace (" \t\n");
		
		while (ss.good()) {
			char line[1024];
			ss.getline(line, 1024);
			
			if (std::string(line).find(mp) != std::string::npos) {
				std::string tmp = std::string(line).substr(std::string(line).find(mp) + mp.size());
				mount_points.push_back(tmp.substr(tmp.find_first_not_of(whitespace), tmp.find_last_not_of(whitespace) - tmp.find_first_not_of(whitespace) + 1));
			}
		}
	}
	
	if (mount_points.size() == 0) {
		std::cerr << "There were no mount points defined." << std::endl;
	}
}

void loadPhysPaths() {
    
    if (mount_points.size() == 0) loadMounts();
    
    for (std::vector<std::string>::iterator itr = mount_points.begin(); itr != mount_points.end(); itr++) {
        std::string phys_path;
        if(plfs_logical_to_physical(itr->c_str(), phys_path) == PLFS_SUCCESS) {
            phys_paths[*itr] = phys_path;
        }
    }
}

int is_plfs_path(const char *path) {

    if(path == NULL) {
        return 0;
    }
 	
 	if (mount_points.size() == 0)
        loadMounts();
 	
 	std::string p(path);
 	int ret = 0;
 	for (std::vector<std::string>::iterator itr = mount_points.begin(); itr != mount_points.end(); itr++) {
 		if (p.find(*itr) != std::string::npos) {
 			ret = 1;
 			break;
 		}
 	}
 	
 	return ret;
}

int getflags(const char *mode) {
    std::string stmode = std::string(mode);

    // Remove 'b' characters since 'b' is ignored by POSIX only used for C98 compatibility
    stmode.erase(std::remove(stmode.begin(), stmode.end(), 'b'), stmode.end());
    
    if (stmode.compare("r") == 0) return O_RDONLY;
    else if (stmode.compare("r+") == 0) return O_RDWR;
    else if (stmode.compare("w") == 0) return O_WRONLY | O_TRUNC | O_CREAT;
    else if (stmode.compare("w+") == 0) return O_RDWR | O_TRUNC | O_CREAT;
    else if (stmode.compare("a") == 0) return O_WRONLY | O_CREAT | O_APPEND;
    else if (stmode.compare("a+") == 0) return O_RDWR | O_CREAT | O_APPEND;
    else return 0;
}

char *resolvefd(int fd) {
    char *path = (char *) malloc(sizeof(char) * 1024);

    char *tmp = (char *) malloc(sizeof(char) * 1024);

    sprintf(tmp, "/proc/self/fd/%d", fd);

    ssize_t len = readlink(tmp, path, 1024);

    path = (char *) realloc(path, len + 1);
    path[len] = '\0';

    free(tmp);

    return path;
}

/* given a relative path, calculate complete path assuming current directory */
char *resolvePath(const char *p) {
	char *ret;

	std::string path (p);

	// if first character isn't "/", prepend current working dir
	if (path[0] != '/') {
		char *cwd = get_current_dir_name();
		path = std::string(cwd) + "/" + path;
		free(cwd);
	}

	if (path.find("/./") != std::string::npos) {
		int stop = path.length()-2;
		// iterate over string... if 3 characters are /./, call replace and replace them with /
		for (int i=0; i < stop; i++) {
			if (path.substr(i,3).compare("/./") == 0) {
				path.replace(i,3,"/");
				stop = path.length()-2;
				i--;
			}
		}
	}       
			
	if (path.find("//") != std::string::npos) {
		int stop = path.length()-1;
		for (int i=0; i < stop; i++) {
			if (path.substr(i,2).compare("//") == 0) {
				path.replace(i,2,"/");
				stop = path.length()-1;
				i--;
			}
		}
	}

	if (path.find("/../") != std::string::npos) {
		// this is the difficult one....
		int stop = path.length()-3;
		int lastslash = 0;
		for (int i=0; i < stop; i++) {
			if (path.substr(i,4).compare("/../") == 0) {
				if (i == 0) {
					path.replace(0,3,"");
					stop = path.length()-3;
					i--;
				} else {
					size_t l = path.find_last_of('/', i-1);
					path.replace(l, i-l+3, "");
					stop = path.length()-3;
					i = l-1;
					// find the previous /
				}
			}
		}
	}

	ret = (char *) malloc((path.length()+1) * sizeof(char));
	strcpy(ret, path.c_str());
	return ret;
}

int isDuplicated(int fd) {
	plfs_file *tmp = plfs_files.find(fd)->second;
	for (std::map<int, plfs_file*>::iterator itr = plfs_files.begin(); itr != plfs_files.end(); itr++) {
		if ((itr->first != fd) && (itr->second == tmp)) return 1; 
	}
	return 0;
}

// create tmp file descriptor
FILE* common_plfs_open(const char* cpath, int flags, mode_t mode) {
	MAP(tmpfile, FILE *(*)(void));

    FILE* ret = NULL;

    plfs_file *tmp = new plfs_file();

    Plfs_open_opt opts;
    opts.index_stream = NULL;
    opts.pinter = PLFS_MPIIO;


    plfs_error_t plfs_error = PLFS_EAGAIN;
    while(plfs_error == PLFS_EAGAIN) {
        plfs_error = plfs_open(&(tmp->fd), cpath, flags, getpid(), mode, NULL);
    }

    off_t size = 0;
    if (flags & O_APPEND) {
        struct stat st;
        plfs_error = PLFS_EAGAIN;
        while (plfs_error == PLFS_EAGAIN) {
            plfs_error = plfs_getattr(tmp->fd, cpath, &st, 1);
        }
        size = st.st_size;
    }

    if(plfs_error != PLFS_SUCCESS) {
        errno = plfs_error_to_errno(plfs_error);
        ret = NULL;
        delete tmp;
    } else {
        ret = __real_tmpfile();
        if (size != 0) {
            fseek(ret, size, SEEK_SET);
            // printf("size: %ld\n", size);
            lseek(fileno(ret), size, SEEK_SET);
        }
        if(ret == NULL) {
            int num_refs = 0;
            plfs_close(tmp->fd, getpid(), getuid(), flags, NULL, &num_refs);
            delete tmp;
        } else {
            tmp->path = new std::string(cpath);
            tmp->flags = flags;
            tmp->tmp_file = ret;
            plfs_files.insert(std::pair<int, plfs_file *>(fileno(ret), tmp));
        }
        // write(1, "plfs_opeq\n", strlen("plfs_open\n")); // using my write function
    }

    return ret;
}

#pragma GCC visibility push(default)

#ifdef __cplusplus
    extern "C" {
#endif



/*
 * File manipulation functions
 *
 * open, creat, read, write, close, sync, fsync, truncate
 *
 */

int open(const char *path, int flags, ...) {
	MAP(open,int (*)(const char*, int, ...));
	
	int ret;
	
	char *cpath = resolvePath(path);


    FILE* tmp_file;
    mode_t mode = 0;
    if ((flags & O_CREAT) == O_CREAT) {
        va_list argf;
        va_start(argf, flags);
        mode = va_arg(argf, mode_t);
        va_end(argf);
    }

    // write(1, "open\n", strlen("open\n")); // using my write function

	if (is_plfs_path(cpath)) {

        FILE* fp = common_plfs_open(cpath, flags, mode);

        // write(1, "plfs_open\n", strlen("plfs_open\n")); // using my write function
        if(fp) {
            ret = fileno(fp);
        } else {
            // write(1, "plfs_opep\n", strlen("plfs_open\n")); // using my write function
            ret = -1;
        }

	} else {
        ret = __real_open(path, flags, mode);
	}
	
	free(cpath);
	return ret;
}


int open64(const char* path, int flags, ...) {
    MAP(open64,int (*)(const char*, int, ...));
    MAP(tmpfile, FILE *(*)(void));
    
    int ret;
    
    char *cpath = resolvePath(path);

    if (is_plfs_path(cpath)) {
        
        write(1, "plfs_ope1\n", strlen("plfs_open\n")); // using my write function
        mode_t mode;
        if ((flags & O_CREAT) == O_CREAT) {
            va_list argf;
            va_start(argf, flags);
            mode = va_arg(argf, mode_t);
            va_end(argf);
        } else {
            plfs_mode(cpath, &mode);
        }
        
        plfs_file *tmp = new plfs_file();
        
        // write(1, "plfs_ope2\n", strlen("plfs_open\n")); // using my write function
        plfs_error_t plfs_error = PLFS_EAGAIN;
        while(plfs_error == PLFS_EAGAIN) {
            plfs_error = plfs_open(&(tmp->fd), cpath, flags, getpid(), mode, NULL);
        }
        // write(1, "plfs_ope3\n", strlen("plfs_open\n")); // using my write function
        if(plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
            ret = -1;
            delete tmp;
        } else {
            ret = fileno(__real_tmpfile());

            tmp->path = new std::string(cpath);
            tmp->flags = flags;

            plfs_files.insert(std::pair<int, plfs_file *>(ret, tmp));
        }
        // write(1, "plfs_ope4\n", strlen("plfs_open\n")); // using my write function
        
    } else {
        if ((flags & O_CREAT) == O_CREAT) {
            va_list argf;
            va_start(argf, flags);
            mode_t mode = va_arg(argf, mode_t);
            va_end(argf);
            ret = __real_open64(path, flags, mode);
        } else {
            ret = __real_open64(path, flags);
        }
    }
    
    free(cpath);
    
    return ret;
}


ssize_t write(int fd, const void *buf, size_t count) {
    MAP(write,ssize_t (*)(int, const void*, size_t));

    ssize_t ret = -1;
    if (plfs_files.find(fd) != plfs_files.end()) {
  
        plfs_file *tmp = plfs_files.find(fd)->second;
        off_t offset = lseek(fd, 0x0, SEEK_CUR);  // tmp fake file descriptor, use system provided seek functions to set different in different process.
        // container global fd.
        
        if(offset != (off_t)-1) {

            plfs_error_t plfs_error = plfs_write(tmp->fd, (const char *) buf, count, offset, getpid(), &ret);

            if(plfs_error != PLFS_SUCCESS) {
                errno = plfs_error_to_errno(plfs_error);
                ret = -1;
            } else {
                lseek(fd, offset + ret, SEEK_SET);
            }
        }
		
    } else {
        ret = __real_write(fd, buf, count);
    }

    return ret;
}

ssize_t read(int fd, void *buf, size_t count) {
    MAP(read,ssize_t (*)(int, void*, size_t));

    ssize_t ret;
    if (plfs_files.find(fd) != plfs_files.end()) {
        
        plfs_file *tmp = plfs_files.find(fd)->second;

        std::string path = *tmp->path;
        const char *pathptr = path.c_str();
        off_t offset = lseek(fd, 0, SEEK_CUR);
        if (offset != (off_t) -1) {
        
            plfs_error_t plfs_error = PLFS_EAGAIN;
            while(plfs_error == PLFS_EAGAIN) {
            	plfs_error = plfs_read(tmp->fd, (char *) buf, count, offset, &ret);
            }

            if(plfs_error != PLFS_SUCCESS) {
            	errno = plfs_error_to_errno(plfs_error);
            	ret = -1;
            } else {
                struct stat filestat;
                plfs_error_t plfs_error = plfs_getattr(tmp->fd, tmp->path->c_str(), &filestat, 0);
                off_t filesize = filestat.st_size;
                offset = offset + ret;
                if (offset >= filesize) {
                    offset = filesize;
                }
                lseek(fd, offset, SEEK_SET);
            }
        }
        
    } else {
        ret = __real_read(fd, buf, count);
    }

    return ret;
}


ssize_t pread(int fd, void* buf, size_t count, off_t offset) {
    MAP(pread, ssize_t (*)(int, void*, size_t, off_t));
    
    ssize_t ret;
    if (plfs_files.find(fd) != plfs_files.end()) {
        plfs_error_t plfs_error = PLFS_EAGAIN;
        while(plfs_error == PLFS_EAGAIN) {
            plfs_error = plfs_read(plfs_files.find(fd)->second->fd, (char *) buf, count, offset, &ret);
        }
        if(plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
            ret = -1;
        } else {
        }
    } else {
        ret = __real_pread(fd, buf, count, offset);
    }
    
    return ret;
}

ssize_t pwrite(int fd, const void* buf, size_t count, off_t offset) {
	MAP(pwrite, ssize_t (*)(int, const void*, size_t, off_t));

    ssize_t ret;
    if (plfs_files.find(fd) != plfs_files.end()) {
	    plfs_error_t plfs_error = plfs_write(plfs_files.find(fd)->second->fd, (const char *) buf, count, offset, getpid(), &ret);
	    if(plfs_error != PLFS_SUCCESS) {
	        errno = plfs_error_to_errno(plfs_error);
	        ret = -1;
	    } else {
	    }
    } else {
	    ret = __real_pwrite(fd, buf, count, offset);
    }

    return ret;
}

ssize_t pread64(int fd, void *buf, size_t count, off64_t offset) {
    MAP(pread64,ssize_t (*)(int, void*, size_t, off64_t));

    ssize_t ret;
    if (plfs_files.find(fd) != plfs_files.end()) {
        
        plfs_error_t plfs_error = PLFS_EAGAIN;
        while(plfs_error == PLFS_EAGAIN) {
            plfs_error = plfs_read(plfs_files.find(fd)->second->fd, (char *) buf, count, offset, &ret);
        }
        if(plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
            ret = -1;
        } else {
        }
        
    } else {
        ret = __real_pread64(fd, buf, count, offset);
    }
    
    return ret;
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off64_t offset) {
    MAP(pwrite64,ssize_t (*)(int, const void*, size_t, off64_t));

    ssize_t ret;
    if (plfs_files.find(fd) != plfs_files.end()) {
        plfs_error_t plfs_error = plfs_write(plfs_files.find(fd)->second->fd, (const char *) buf, count, offset, getpid(), &ret);
        if(plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
            ret = -1;
        } else {
        }
        
    } else {
        ret = __real_pwrite64(fd, buf, count, offset);
    }

    return ret;
}


int close(int fd) {
	MAP(close, int (*)(int));
	MAP(fclose, int (*)(FILE*));
	
	int num_refs;

    int ret;
	if (plfs_files.find(fd) != plfs_files.end()) {
        plfs_file *tmp = plfs_files.find(fd)->second;
		
		if (!isDuplicated(fd)) {
			plfs_error_t plfs_error = plfs_close(tmp->fd, getpid(), getuid(), tmp->flags, NULL, &num_refs);
			delete tmp->path;
			delete tmp;
        }
        // ret = __real_fclose(tmp->tmp_file);
		plfs_files.erase(fd);
    }

    ret = __real_close(fd);

    return ret;
}


char* get_current_dir_name(void) {
    MAP(get_current_dir_name, char* (*)(void));
    
    char* ret = NULL;
    
    if (phys_paths.size() == 0) loadPhysPaths();
    
    char* real_cwd = __real_get_current_dir_name();
    std::string real_cwd_str(real_cwd);
    free(real_cwd);
    
    for (std::map<std::string, std::string>::iterator itr = phys_paths.begin(); itr != phys_paths.end(); itr++) {
        size_t found_pos = real_cwd_str.find(itr->second);
        if (found_pos == 0 && itr->second != "") {
            real_cwd_str.erase(found_pos, itr->second.size());
            real_cwd_str.insert(found_pos, itr->first);
            break;
        }
    }
    
    ret = (char*)malloc(real_cwd_str.size()+1);
    memset(ret, 0x00, real_cwd_str.size()+1);
    memcpy(ret, real_cwd_str.data(), real_cwd_str.size());

    
    return ret;
}


// FILE operations
//
FILE* fopen(const char* pathname, const char* mode) {
	MAP(fopen, FILE* (*)(const char*, const char*));
	MAP(tmpfile, FILE *(*)(void));  // to build fake descriptor
	
    FILE* ret;
	
	char *cpath = resolvePath(pathname);
    int flags = getflags(mode);

	if (is_plfs_path(cpath)) {
        mode_t m = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
        FILE* fp = common_plfs_open(cpath, flags, m);
        if(fp == NULL) {
            ret = NULL;
        }
	} else {
        ret = __real_fopen(pathname, mode);
	}
	
	free(cpath);
	return ret;
}

size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream) {
    MAP(fread, size_t (*)(void*, size_t, size_t, FILE*));

    int fd = fileno(stream);

    ssize_t ret;
    if (plfs_files.find(fd) != plfs_files.end()) {
        
        plfs_file *tmp = plfs_files.find(fd)->second;

        long offset = ftell(stream);    // get current FILE offset
        if (offset != (off_t) -1) {
        
            plfs_error_t plfs_error = PLFS_EAGAIN;
            while(plfs_error == PLFS_EAGAIN) {
            	plfs_error = plfs_read(tmp->fd, (char *) ptr, size*nmemb, offset, &ret);
            }

            if(plfs_error != PLFS_SUCCESS) {
            	errno = plfs_error_to_errno(plfs_error);
            	ret = -1;
            } else {
                fseek(stream, ret, SEEK_CUR);   // update FILE offset
            }
        }
    } else {
        ret = __real_fread(ptr, size, nmemb, stream);
    }

    return ret;
}

size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream) {
    MAP(fwrite, size_t (*)(const void* ptr, size_t, size_t, FILE*));
	
    int fd = fileno(stream);
    ssize_t ret = -1;
    if (plfs_files.find(fd) != plfs_files.end()) {

        // write(1, "plfs_open\n", strlen("plfs_open\n")); // using my write function
        plfs_file *tmp = plfs_files.find(fd)->second;   // fake file descriptor
        off_t offset = ftell(stream);
        
        if(offset != (off_t)-1) {

            plfs_error_t plfs_error = plfs_write(tmp->fd, (const char *) ptr, size * nmemb, offset, getpid(), &ret);

            if(plfs_error != PLFS_SUCCESS) {
                errno = plfs_error_to_errno(plfs_error);
                ret = -1;
            } else {
                fseek(stream, ret, SEEK_CUR);
            }
        }
    } else {
        ret = __real_fwrite(ptr, size, nmemb, stream);
    }

    return ret;
}

int fclose(FILE* stream) {
	MAP(fclose, int (*)(FILE*));
	
	int num_refs;
    int fd = fileno(stream);

	if (plfs_files.find(fd) != plfs_files.end()) {
		
        plfs_file *tmp = plfs_files.find(fd)->second;

		if (!isDuplicated(fd)) {
			plfs_error_t plfs_error = plfs_close(tmp->fd, getpid(), getuid(), tmp->flags, NULL, &num_refs);
			delete plfs_files.find(fd)->second->path;
			delete plfs_files.find(fd)->second;
		}
		plfs_files.erase(fd);
	}
	
	int ret = __real_fclose(stream);

    return ret;
}

int chmod(const char* pathname, mode_t mode) {
    MAP(chmod, int (*)(const char*, mode_t));

    int ret;
    char* cpath = resolvePath(pathname);

    if (is_plfs_path(cpath)) {
        plfs_error_t plfs_error = plfs_chmod(cpath, mode);
        if (plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
            ret = -1;
        } else {
            ret = 0;
        }
    } else {
        ret = __real_chmod(cpath, mode);
    }

    free(cpath);

    return ret;
}



int fgetc(FILE* stream) {
    MAP(fgetc, int(*)(FILE*));
    MAP(getc, int(*)(FILE*));

    int fd = fileno(stream);
    ssize_t ret;
    char c;

    if (plfs_files.find(fd) != plfs_files.end()) {
        plfs_file* tmp = plfs_files.find(fd)->second;
        
        off_t offset = ftell(stream);
        if (offset != (off_t)-1) {
            plfs_error_t plfs_error = plfs_read(tmp->fd, &c, 1, offset, &ret);
            while (plfs_error == PLFS_EAGAIN) {
                plfs_error = plfs_read(tmp->fd, &c, 1, offset, &ret);
            }
            if (plfs_error != PLFS_SUCCESS) {
                errno = plfs_error_to_errno(plfs_error);
                ret = EOF;
            } else {
                fseek(stream, ret, SEEK_CUR);
            }
        }
    } else {
        c = __real_fgetc(stream);   // getc?
    }

    return c;
}

int getc(FILE* stream) {
    return fgetc(stream);
}

char* fgets(char* str, int count, FILE* stream) {
    MAP(fgets, char*(*)(char*, int, FILE*));

    int fd = fileno(stream);
    ssize_t ret;
    
    if (plfs_files.find(fd) != plfs_files.end()) {
        plfs_file* tmp = plfs_files.find(fd)->second;

        off_t offset = ftell(stream);
        if (offset != (off_t)-1) {
            plfs_error_t plfs_error = plfs_read(tmp->fd, str, count, offset, &ret);
            while (plfs_error == PLFS_EAGAIN) {
                plfs_error = plfs_read(tmp->fd, str, count, offset, &ret);
            }

            if (plfs_error != PLFS_SUCCESS) {
                errno = plfs_error_to_errno(plfs_error);
                ret = -1;
            } else {
                fseek(stream, ret, SEEK_CUR);
            }
        }
    } else {
        str = __real_fgets(str, count, stream);
    }

    return str;
}



int fputc(int ch, FILE* stream) {
    MAP(fputc, int(*)(int, FILE*));
    MAP(putc, int(*)(int, FILE*));

    int fd = fileno(stream);
    ssize_t ret;

    char c = ch;
    if (plfs_files.find(fd) != plfs_files.end()) {
        plfs_file* tmp = plfs_files.find(fd)->second;

        off_t offset = ftell(stream);
        plfs_error_t plfs_error = plfs_write(tmp->fd, &c, 1, offset, getpid(), &ret);
        while (plfs_error = PLFS_EAGAIN) {
            plfs_error = plfs_write(tmp->fd, &c, 1, offset, getpid(), &ret);
        }

        if (plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
            ret = -1;
        } else {
            fseek(stream, ret, SEEK_CUR);
        }
    } else {
        ret = __real_fputc(ch, stream);
    }

    return ret;
}

int putc(int c, FILE* stream) {
    return fputc(c, stream);
}


int fputs(const char* str, FILE* stream) {
    MAP(fputs, int(*)(const char*, FILE*));

    int fd = fileno(stream);
    int ret;

    if (plfs_files.find(fd) != plfs_files.end()) {
        plfs_file* tmp = plfs_files.find(fd)->second;

        off_t offset = ftell(stream);
        int len = strlen(str);
        ssize_t bytes = 0;
        ssize_t written = 0;

        if (offset != (off_t)-1) {
            plfs_error_t plfs_error = plfs_write(tmp->fd, str+written, len-written, offset, getpid(), &bytes);
            written += bytes;
            offset += bytes;
            while (plfs_error == PLFS_EAGAIN) {
                plfs_error = plfs_write(tmp->fd, str+written, len-written, offset, getpid(), &bytes);
                written += bytes;
                offset += bytes;
            }

            if (plfs_error != PLFS_SUCCESS) {
                ret = EOF;
                errno = plfs_error_to_errno(plfs_error);
                ret = written;
            } else {
                fseek(stream, written, SEEK_CUR);
                ret = written;
            }
        }
    } else {
        ret = __real_fputs(str, stream);
    }

    return ret;
}

int puts(const char* str) {
    MAP(puts, int(*)(const char *));

    int fd = fileno(stdout);
    int ret;

    if (plfs_files.find(fd) != plfs_files.end()) {
        ret = fputs(str, stdout);   // my fputs
    } else {
        ret = __real_puts(str);
    }

    return ret;
}



int mkdir(const char* pathname, mode_t mode) {
    MAP(mkdir, int(*)(const char*, mode_t));

    char* path = resolvePath(pathname);

    int ret = 0;
    if (is_plfs_path(path)) {
        plfs_error_t plfs_error = plfs_mkdir(path, mode);
        if (plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
            ret = -1;
        }
    } else {
        ret = __real_mkdir(pathname, mode);
    }

    free(path);

    return ret;
}


int rmdir(const char* pathname) {
    MAP(rmdir, int (*)(const char *));
    
    int ret = 0;
    
    char *path = resolvePath(pathname);
    if (is_plfs_path(path)) {
        
        plfs_error_t plfs_error = plfs_rmdir(path);
        if(plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
            ret = -1;
        } else {
            ret = 0;
        }
        
    } else {
        ret = __real_rmdir(pathname);
    }
    
    free(path);

    return ret;
}


DIR* opendir(const char* pathname) {
    MAP(opendir, DIR*(*)(const char*));

    DIR* key;
    char *path = resolvePath(pathname);

    if (is_plfs_path(path)) {
        key = __real_opendir("/");

        plfs_dir* d = new plfs_dir();
        d->path = new std::string(path);
        d->files = new std::set<std::string>();

        plfs_error_t plfs_error = plfs_readdir(path, (void*)d->files);
        if (plfs_error != PLFS_SUCCESS) {
            delete d->path;
            delete d->files;
            delete d;
            return NULL;
        }

        d->iter = d->files->begin();
        d->dirFd = dirfd(key);

        opendirs.insert(std::pair<DIR*, plfs_dir*>(key, d));
        fd2dir.insert(std::pair<int, DIR*>(d->dirFd, key));
    } else {
        key = __real_opendir(pathname);
    }

    free(path);

    return key;
}


struct dirent* readdir(DIR* dir) {
    MAP(readdir, struct dirent*(*)(DIR*));

    struct dirent* ret;

    if (opendirs.find(dir) != opendirs.end()) {
        plfs_dir* d = opendirs.find(dir)->second;

        if (d->iter == d->files->end()) {
            ret = NULL; // final entry
        } else {
            static struct dirent tmp;
            std::string path(*(d->path));
            path += "/";
            path += d->iter->c_str();

            struct stat stats;
            plfs_getattr(NULL, path.c_str(), &stats, 0);

            tmp.d_ino = stats.st_ino;
            sprintf(tmp.d_name, "%s", d->iter->c_str());

            ret = &tmp;
            d->iter++;  // move to the next entry
        }
    } else {
        ret = __real_readdir(dir);
    }

    return ret;
}


int closedir(DIR* dir) {
    MAP(closedir, int(*)(DIR*));

    if (opendirs.find(dir) != opendirs.end()) {
        plfs_dir* tmp = opendirs.find(dir)->second;
        fd2dir.erase(tmp->dirFd);
        delete tmp->path;
        delete tmp;
        
        opendirs.erase(dir);
    }

    return __real_closedir(dir);
}


int chdir(const char* pathname) {
    MAP(chdir, int(*)(const char*));

    int ret = 0;
    char* path = resolvePath(pathname);

    if (is_plfs_path(path)) {
        char* phys_path = NULL;
        char* mountp = NULL;
        char* backp = NULL;

        plfs_error_t plfs_error = plfs_expand_path(path, &phys_path, (void**)&(mountp), (void**)&backp);
        if (plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
            ret = -1;
        } else {
            ret = __real_chdir(phys_path);
            free(phys_path);
        }
    } else {
        ret = __real_chdir(path);
    }

    return ret;
}


char* getcwd(char* buf, size_t size) {
    MAP(get_current_dir_name,char* (*)(void));
    
    char* ret = NULL;
    
    if(buf != NULL && size == 0) {
        errno = EINVAL;
        ret = NULL;
    } else {
        if (phys_paths.size() == 0) loadPhysPaths();
        
        char* real_cwd = __real_get_current_dir_name();
        std::string real_cwd_str(real_cwd);
        free(real_cwd);
            
        for (std::map<std::string, std::string>::iterator itr = phys_paths.begin(); itr != phys_paths.end(); itr++) {
            size_t found_pos = real_cwd_str.find(itr->second);
            if (found_pos == 0 && itr->second != "") {
                real_cwd_str.erase(found_pos, itr->second.size());
                real_cwd_str.insert(found_pos, itr->first);
                break;
            }
        }
        
        // POSIX.1-2001 standard
        if(buf == NULL) {
            if(size == 0) {
                size = real_cwd_str.size()+1;
            }
            buf = (char*)malloc(size);
        }
        
        if(real_cwd_str.size()+1 > size) {
            errno = ERANGE;
            ret = NULL;
        } else {
            memset(buf, 0x00, size);
            strncpy(buf, real_cwd_str.c_str(), size);
            ret = buf;
        }
    }
	
    return ret;
}


int fcntl(int fildes, int cmd, ...){
	MAP(fcntl,int (*)(int, int, ...));

    int ret;

    va_list vl;
    va_start(vl, cmd);
    switch (cmd) {
        case F_DUPFD:
        case F_DUPFD_CLOEXEC:
        case F_GETFD:
        case F_SETFD:
        case F_GETFL:
        case F_SETFL:
        case F_GETOWN:
        case F_SETOWN:
        {
            int arg = va_arg(vl,int);
            ret = __real_fcntl(fildes, cmd, arg);
            break;
        }

        case F_GETLK:
        case F_SETLK:
        case F_SETLKW:
        {
            struct flock* arg = va_arg(vl,struct flock*);
            ret = __real_fcntl(fildes, cmd, arg);
            break;
        }
    }
    va_end(vl);
    
    if (plfs_files.find(fildes) != plfs_files.end()) {
        if(cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
            if(ret != -1) {
                plfs_file *tmp = plfs_files.find(fildes)->second;
                plfs_files.insert(std::pair<int, plfs_file *>(ret, tmp));
            }
        }
    }

    return ret;
}

int rename(const char* frompath, const char* topath) {
    MAP(rename, int (*)(const char *, const char *));
    
    int ret = 0;
    
    char *path_from = resolvePath(frompath);
    char *path_to = resolvePath(topath);
    if (is_plfs_path(path_from) && is_plfs_path(path_to)) {
        plfs_error_t plfs_error = plfs_rename(path_from, path_to);
        if(plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
            ret = -1;
        } else {
            ret = 0;
        }
    } else if (is_plfs_path(path_from) || is_plfs_path(path_to)) {
        errno = ENOENT;
        ret = -1;
    } else {
        ret = __real_rename(frompath, topath);
    }

    free(path_from);
    free(path_to);

    return ret;
}



int fflush(FILE* stream) {
	MAP(fflush, int (*)(FILE *));
    
	int ret;
	
	// If fflush(NULL), sync all open files - including the PLFS ones
	if (NULL == stream) {
		for (std::map<int,plfs_file*>::iterator itr = plfs_files.begin(); itr != plfs_files.end(); itr++) {
			plfs_sync(itr->second->fd);
		}
		return __real_fflush(stream);
	}

	if (plfs_files.find(fileno(stream)) != plfs_files.end()) {
		plfs_error_t plfs_error = plfs_sync(plfs_files.find(fileno(stream))->second->fd);
		if(plfs_error != PLFS_SUCCESS) {
			errno = plfs_error_to_errno(plfs_error);
			ret = EOF;
		} else {
			ret = 0;
		}
	} else {
		ret = __real_fflush(stream);
	}
	
	return ret;
}


int unlink(const char* pathname) {
    MAP(unlink, int (*)(const char *));
   
    int ret = 0;
    
    char *path = resolvePath(pathname);
    if (is_plfs_path(path)) {
        
        plfs_error_t plfs_error = plfs_unlink(path);
        if(plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
            ret = -1;
        } else {
            ret = 0;
        }
    } else {
        ret = __real_unlink(pathname);
    }
    
    free(path);

    return ret;
}

int vfprintf(FILE *stream, const char *format, va_list ap) {
    MAP(vfprintf, int(*)(FILE *stream, const char *format, va_list ap));

    int ret;

	if (plfs_files.find(fileno(stream)) != plfs_files.end()) {
        char* out_buffer = NULL;
        int out_length = vasprintf(&out_buffer, format, ap);
		long offset = ftell(stream);
		ssize_t bytes;
		plfs_error_t plfs_error = plfs_write(plfs_files.find(fileno(stream))->second->fd, out_buffer, out_length, offset, getpid(), &bytes);
		
        if(plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
			ret = -1;
        } else {
            fseek(stream, bytes, SEEK_CUR);
			ret = bytes;
        }
        free(out_buffer);
	} else {
		ret = __real_vfprintf(stream, format, ap);
	}

	return ret;
}


int fprintf(FILE* stream, const char* format, ...) {
    va_list arg;
    int ret;

    va_start(arg, format);
    ret = vfprintf(stream, format, arg);
    va_end(arg);

    return ret;
}



// int stat(const char* pathname, struct stat* statbuf) {
//     MAP(stat, int(*)(const char*, struct stat*));
// 	int ret = 0;
//     
// 	char *cpath = resolvePath(pathname);
//     write(1, "stat\n", strlen("stat\n")); // using my write function
//     
//     if (is_plfs_path(cpath)) {
//         plfs_error_t plfs_error = plfs_getattr(NULL, cpath, statbuf, 0);
//         while (plfs_error = PLFS_EAGAIN) {
//             plfs_error = plfs_getattr(NULL, cpath, statbuf, 0);
//         }
// 
//         if (plfs_error != PLFS_SUCCESS) {
//             ret = -1;
//         }
//     } else {
//         ret = __real_stat(cpath, statbuf);
//     }
// 
//     free(cpath);
//     return ret;
// }

int __lxstat(int vers, const char* path, struct stat* statbuf) {
    MAP(__lxstat, int(*)(int, const char*, struct stat*));
    int ret = 0;
    char* cpath = resolvePath(path);

    if (is_plfs_path(cpath)) {
        plfs_error_t plfs_error = plfs_getattr(NULL, cpath, statbuf, 0);
        while (plfs_error == PLFS_EAGAIN) {
            plfs_error = plfs_getattr(NULL, cpath, statbuf, 0);
        }

        if (plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
            ret = -1;
        }
    } else {
        ret = __real___lxstat(vers, path, statbuf);
    }
}



int __xstat(int vers, const char *path, struct stat *buf) {
    MAP(__xstat, int(*)(int, const char*, struct stat*));
    int ret = 0;
    char* cpath = resolvePath(path);

    if (is_plfs_path(cpath)) {
        plfs_error_t plfs_error = plfs_getattr(NULL, cpath, buf, 0);
        while (plfs_error == PLFS_EAGAIN) {
            plfs_error = plfs_getattr(NULL, cpath, buf, 0);
        }

        if (plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
            ret = -1;
        }
    } else {
        ret = __real___xstat(vers, cpath, buf);
    }

    free(cpath);
    return ret;
}

int __fxstat(int vers, int fd, struct stat *buf) {
    MAP(__fxstat, int(*)(int, int, struct stat*));
    int ret = 0;

    if (plfs_files.find(fd) != plfs_files.end()) {
        plfs_file* tmp = plfs_files.find(fd)->second;
        plfs_error_t plfs_error = plfs_getattr(tmp->fd, NULL, buf, 0);
        while (plfs_error == PLFS_EAGAIN) {
            plfs_error = plfs_getattr(tmp->fd, NULL, buf, 0);
        }

        if (plfs_error != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(plfs_error);
            ret = -1;
        }
    } else {
        ret = __real___fxstat(vers, fd, buf);
    }

    return ret;
}

#ifdef __cplusplus
#endif
}
#pragma GCC visibility push(default)

