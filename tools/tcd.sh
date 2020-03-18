tcd() {
    x=`~/dev/stage/Tardis/tools/tcd.py $1`
    if [ $? -eq 0 ]
    then
        cd $x;
    fi
    echo -e "\e[1m`pwd`"
}
