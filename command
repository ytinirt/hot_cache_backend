#!/bin/bash

# 所有export的变量都能在子任务、make中看到
export ROOT=$(pwd)
export ROOT_NGX=${ROOT}/android_nginx
export ROOT_PUBLIB=${ROOT}/pub_lib
export ROOT_AUTHEN=${ROOT}/authen_nginx_module
export ROOT_CACHE_RULE=${ROOT}/cache_rule
export ROOT_CURL=${ROOT_PUBLIB}/curl-7.45.0
export SC=snooping_client
export ROOT_SC=${ROOT}/${SC}

export CONF=${ROOT}/conf
export CACHE_RULE_FILE=hot_cache.rule
export NGINX_CONF_FILE=nginx.conf

export CACHE_RULE_LIB=${ROOT_CACHE_RULE}/libcacherule.a

export TMP=${ROOT}/tmp
export TMP_CURL_LIB=${TMP}/libcurl
export TMP_SC=${TMP}/${SC}

export PREFIX=/data/local
export PREFIX_NGX=${PREFIX}/nginx
export PREFIX_SC=${PREFIX}/${SC}

# 编译和链接标志
export CC=`which arm-linux-androideabi-gcc`
export LD=`which arm-linux-androideabi-ld`
export AR=`which arm-linux-androideabi-ar`
export ADB=`which adb`

function check_check {
    if [ ${CC}x = "x" ]; then
        echo "未找到编译器: arm-linux-androideabi-gcc"
        return 1
    fi
    if [ ${LD}x = "x" ]; then
        echo "未找到链接器: arm-linux-androideabi-ld"
        return 1
    fi
    if [ ${AR}x = "x" ]; then
        echo "未找到归档器: arm-linux-androideabi-ar"
        return 1
    fi

    if [ ${ADB}x = "x" ]; then
        echo "未找到Android调试工具: adb"
        return 1
    fi

    adb shell echo "test" &> /dev/null
    if [ $? != 0 ]; then
        echo "未连接电视盒子"
        return 1
    fi

    echo "编译环境正常，可以继续操作"
    return 0
}

function clean_clean {
    cd ${ROOT_CURL}
    echo "Enter $ROOT_CURL"
    make distclean
    echo "Leave $ROOT_CURL"
    echo ""

    cd ${ROOT_CACHE_RULE}
    echo "Enter $ROOT_CACHE_RULE"
    make clean
    echo "Leave $ROOT_CACHE_RULE"
    echo ""

    cd ${ROOT_NGX}
    echo "Enter $ROOT_NGX"
    make clean
    echo "Leave $ROOT_NGX"
    echo ""

    echo rm -rf $TMP
    rm -rf $TMP
}

function adb_push {
    adb push $1 ${PREFIX_NGX}/$1
}

function install_install {
    echo Enter $ROOT_NGX
    cd ${ROOT_NGX}
    adb shell mkdir -p $PREFIX_NGX
    adb push objs/nginx ${PREFIX_NGX}/sbin/nginx
    adb shell chmod 755 ${PREFIX_NGX}/sbin/nginx
    adb_push conf/koi-win
    adb_push conf/koi-utf
    adb_push conf/win-utf
    adb_push conf/mime.types
    adb_push conf/fastcgi_params
    adb_push conf/fastcgi.conf
    adb_push conf/uwsgi_params
    adb_push conf/scgi_params
    adb_push conf/nginx.conf
    adb shell mkdir -p ${PREFIX_NGX}/logs
    adb push docs/html ${PREFIX_NGX}/html
    echo "Leave $ROOT_NGX"
    echo ""

    echo Enter $TMP
    cd $TMP
    adb shell mkdir -p $PREFIX_SC
    adb push $SC ${PREFIX_SC}/$SC
    adb shell chmod 755 ${PREFIX_SC}/$SC
    echo "Leave $TMP"
    echo ""
    
    upload_conf_file
}

function upload_conf_file {
    echo Enter $CONF
    cd $CONF
    adb push $CACHE_RULE_FILE ${PREFIX_SC}/$CACHE_RULE_FILE
    adb push $NGINX_CONF_FILE ${PREFIX_NGX}/conf/$NGINX_CONF_FILE
    echo "Leave $CONF"
    echo ""
}

# 脚本从这里开始执行
case "$1" in
    # 检查环境是否准备好
    check)
        check_check
        exit 0
        ;;
    # 将交叉编译好的可执行文件安装到电视盒子
    install)
        install_install
        exit 0
        ;;
    # 清理所有所有文件，恢复如初
    clean)
        clean_clean
        exit 0
        ;;
    # 上传所有配置
    uploadConf)
        upload_conf_file
        exit 0
        ;;
    # 执行交叉编译操作
    compile)
        # 继续后面的操作
        ;;
    # 默认情况，显示帮助信息
    *)
        echo "check      - 检查编译环境"
        echo "compile    - 编译"
        echo "install    - 安装到电视盒子"
        echo "clean      - 清理编译环境"
        echo "uploadConf - 上传配置文件到电视盒子"
        exit 0
        ;;
esac

# 【第1步】交叉编译Nginx
cd $ROOT_NGX
echo "Enter $ROOT_NGX"
if [ ! -e ${ROOT_NGX}/Makefile ]; then
    echo "Makefile not exists, configure first."
    auto/configure --crossbuild=android-arm --prefix=${PREFIX_NGX} \
                   --with-cc=${CC} \
                   --without-http_userid_module --with-cc-opt=-Wno-sign-compare \
                   --with-http_mp4_module --with-http_flv_module \
                   --with-pcre=${ROOT_PUBLIB}/pcre-8.34 \
                   --add-module=${ROOT_AUTHEN}
fi
# 执行编译
make
echo "Leave $ROOT_NGX"
echo ""

# 【第2步】交叉编译缓存匹配算法库
cd $ROOT_CACHE_RULE
echo "Enter $ROOT_CACHE_RULE"
# 执行编译库的操作
make androidlib
echo "Leave $ROOT_CACHE_RULE"
echo ""

# 【第3步】交叉编译libcurl
cd $ROOT_CURL
echo "Enter $ROOT_CURL"
if [ ! -e ${ROOT_CURL}/Makefile ]; then
    echo "Makefile not exists, configure first."
    ./configure --host=arm-linux-androideabi --prefix=$TMP_CURL_LIB
fi
# 执行编译和安装库的操作
make && make install
cd $TMP_CURL_LIB
export CURL_CFLAG=`./bin/curl-config --cflags`
export CURL_STATIC_LIB=`./bin/curl-config --static-libs`
echo "Leave $ROOT_CURL"
echo ""

# 【第4步】交叉编译Snooping Client
cd $ROOT_SC
echo "Enter $ROOT_SC"
# 对于Snooping Client，采用肉搏方式直接编译
echo $CC -o $TMP_SC ${SC}.c $CURL_CFLAG $CURL_STATIC_LIB $CACHE_RULE_LIB
$CC -o $TMP_SC ${SC}.c $CURL_CFLAG $CURL_STATIC_LIB $CACHE_RULE_LIB
echo "Leave $ROOT_SC"
echo ""

