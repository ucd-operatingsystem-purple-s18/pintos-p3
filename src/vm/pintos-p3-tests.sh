#!/bin/bash
# PINTOS-P3: USERPROG -- ITEMIZED PASS/FAIL TESTING SCRIPT (for use with QEMU)
# By: John B - Influenced by Brian, Matthew, and Michael -- UCDenver CSCI 3453, Spring 2018

# NOTE: To allow execution of this script, run the following command:
#   chmod +x ./pintos-*-tests.sh


main () 
{
    echo -e "PINTOS-P3: USERPROG -- ITEMIZED PASS/FAIL TESTING SCRIPT\n"
    echo -e "NOTE: This script must be run from your Pintos 'src/userprog/' directory.\n"
    echo -e "This script will build Pintos, and if successful, will use QEMU"
    echo -e "to execute the tests that are not commented out in this script.\n"
    read -p "Press the [ENTER] key to continue, or [CTRL]+[C] to abort testing."

    echo -e "\n   BUILDING PINTOS: \n"
    make all
    BUILD_SUCCESS=!$?
    
    if (( $BUILD_SUCCESS )); then
        
        cd build
        let "pass = 0"
        let "total = 0"
        
        # Run all the following tests that are not commented out:

        test-args-none
        # test-args-single
        # test-args-multiple
        # test-args-many
        # test-args-dbl-space

        # test-sc-bad-sp
        # test-sc-bad-arg
        # test-sc-boundary
        # test-sc-boundary-2

        # test-halt
        # test-exit

        # test-create-normal
        # test-create-empty
        # test-create-null
        # test-create-bad-ptr
        # test-create-long
        # test-create-exists
        # test-create-bound

        # test-open-normal
        # test-open-missing
        # test-open-boundary
        # test-open-empty
        # test-open-null
        # test-open-bad-ptr
        # test-open-twice

        # test-close-normal
        # test-close-twice
        # test-close-stdin
        # test-close-stdout
        # test-close-bad-fd

        # test-read-normal
        # test-read-bad-ptr
        # test-read-boundary
        # test-read-zero
        # test-read-stdout
        # test-read-bad-fd

        # test-write-normal
        # test-write-bad-ptr
        # test-write-boundary
        # test-write-zero
        # test-write-stdin
        # test-write-bad-fd

        # test-exec-once
        # test-exec-arg
        # test-exec-multiple
        # test-exec-missing
        # test-exec-bad-ptr

        # test-wait-simple
        # test-wait-twice
        # test-wait-killed
        # test-wait-bad-pid

        # test-multi-recurse
        # test-multi-child-fd

        # test-rox-simple
        # test-rox-child
        # test-rox-multichild

        # test-bad-read
        # test-bad-write
        # test-bad-read2
        # test-bad-write2
        # test-bad-jump
        # test-bad-jump2

        # test-lg-create
        # test-lg-full
        # test-lg-random
        # test-lg-seq-block
        # test-lg-seq-random

        # test-sm-create
        # test-sm-full 
        # test-sm-random
        # test-sm-seq-block 
        # test-sm-seq-random

        # test-syn-read 
        # test-syn-remove 
        # test-syn-write

        # test-pt-grow-stack
        # test-pt-grow-pusha
        # test-pt-grow-bad
        # test-pt-big-stk-obj
        # test-pt-bad-addr
        # test-pt-bad-read
        # test-pt-write-code
        # test-pt-write-code2
        # test-pt-grow-stk-sc

        # test-page-linear
        # test-page-parallel
        # test-page-merge-seq
        # test-page-merge-par
        # test-page-merge-stk
        # test-page-merge-mm
        # test-page-shuffle

        # test-mmap-read
        # test-mmap-close
        # test-mmap-unmap
        # test-mmap-overlap
        # test-mmap-twice
        # test-mmap-write
        # test-mmap-exit
        # test-mmap-shuffle
        # test-mmap-bad-fd
        # test-mmap-clean
        # test-mmap-inherit
        # test-mmap-misalign
        # test-mmap-null
        # test-mmap-over-code
        # test-mmap-over-data
        # test-mmap-over-stk
        # test-mmap-remove
        # test-mmap-zero

        
        echo -e "\n   SCRIPT EXECUTION TERMINATED SUCCESSFULLY. \n"
        echo "Pass: $pass" 
        echo "Total: $total"
    else 
        echo -e "\n   ERROR:  FAILED TO BUILD PINTOS.  NO TESTS WERE RUN. \n"
    fi
}


test-args-none() 
{
    let "total = total + 1"   
    echo -e "\n   RUNNING TEST:   args-none \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/args-none -a args-none --swap-size=4 -- -q -f run args-none < /dev/null 2> tests/userprog/args-none.errors |tee tests/userprog/args-none.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/args-none.ck tests/userprog/args-none tests/userprog/args-none.result
    if grep -q "PASS" tests/userprog/args-none.result 
        then let "pass = pass + 1"
    fi
}

test-args-single() 
{    
    let "total = total + 1"   
    echo -e "\n   RUNNING TEST:   args-single \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/args-single -a args-single --swap-size=4 -- -q -f run 'args-single onearg' < /dev/null 2> tests/userprog/args-single.errors |tee tests/userprog/args-single.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/args-single.ck tests/userprog/args-single tests/userprog/args-single.result
    if grep -q "PASS" tests/userprog/args-single.result
        then let "pass = pass + 1"
    fi
}

test-args-multiple() 
{    
    let "total = total + 1"   
    echo -e "\n   RUNNING TEST:   args-multiple \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/args-multiple -a args-multiple --swap-size=4 -- -q -f run 'args-multiple some arguments for you!' < /dev/null 2> tests/userprog/args-multiple.errors |tee tests/userprog/args-multiple.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/args-multiple.ck tests/userprog/args-multiple tests/userprog/args-multiple.result
    if grep -q "PASS" tests/userprog/args-multiple.result
        then let "pass = pass + 1"
    fi
}

test-args-many() 
{
    let "total = total + 1"   
    echo -e "\n   RUNNING TEST:   args-many \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/args-many -a args-many --swap-size=4 -- -q -f run 'args-many a b c d e f g h i j k l m n o p q r s t u v' < /dev/null 2> tests/userprog/args-many.errors |tee tests/userprog/args-many.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/args-many.ck tests/userprog/args-many tests/userprog/args-many.result
    if grep -q "PASS" tests/userprog/args-many.result
        then let "pass = pass + 1"
    fi
}

test-args-dbl-space() 
{
    let "total = total + 1"      
    echo -e "\n   RUNNING TEST:   args-dbl-space \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/args-dbl-space -a args-dbl-space --swap-size=4 -- -q -f run 'args-dbl-space two spaces!' < /dev/null 2> tests/userprog/args-dbl-space.errors |tee tests/userprog/args-dbl-space.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/args-dbl-space.ck tests/userprog/args-dbl-space tests/userprog/args-dbl-space.result
    if grep -q "PASS" tests/userprog/args-dbl-space.result
        then let "pass = pass + 1"
    fi
}

test-sc-bad-sp() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   sc-bad-sp \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/sc-bad-sp -a sc-bad-sp --swap-size=4 -- -q -f run sc-bad-sp < /dev/null 2> tests/userprog/sc-bad-sp.errors |tee tests/userprog/sc-bad-sp.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/sc-bad-sp.ck tests/userprog/sc-bad-sp tests/userprog/sc-bad-sp.result
    if grep -q "PASS" tests/userprog/sc-bad-sp.result
        then let "pass = pass + 1"
    fi
}

test-sc-bad-arg() 
{    
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   sc-bad-arg \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/sc-bad-arg -a sc-bad-arg --swap-size=4 -- -q -f run sc-bad-arg < /dev/null 2> tests/userprog/sc-bad-arg.errors |tee tests/userprog/sc-bad-arg.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/sc-bad-arg.ck tests/userprog/sc-bad-arg tests/userprog/sc-bad-arg.result
    if grep -q "PASS" tests/userprog/sc-bad-arg.result
        then let "pass = pass + 1"
    fi
}

test-sc-boundary() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   sc-boundary \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/sc-boundary -a sc-boundary --swap-size=4 -- -q -f run sc-boundary < /dev/null 2> tests/userprog/sc-boundary.errors |tee tests/userprog/sc-boundary.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/sc-boundary.ck tests/userprog/sc-boundary tests/userprog/sc-boundary.result
    if grep -q "PASS" tests/userprog/sc-boundary.result
        then let "pass = pass + 1"
    fi
}

test-sc-boundary-2() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   sc-boundary-2 \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/sc-boundary-2 -a sc-boundary-2 --swap-size=4 -- -q -f run sc-boundary-2 < /dev/null 2> tests/userprog/sc-boundary-2.errors |tee tests/userprog/sc-boundary-2.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/sc-boundary-2.ck tests/userprog/sc-boundary-2 tests/userprog/sc-boundary-2.result
    if grep -q "PASS" tests/userprog/sc-boundary-2.result
        then let "pass = pass + 1"
    fi
}

test-halt() 
{    
    let "total = total + 1"  
    echo -e "\n   RUNNING TEST:   halt \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/halt -a halt --swap-size=4 -- -q -f run halt < /dev/null 2> tests/userprog/halt.errors |tee tests/userprog/halt.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/halt.ck tests/userprog/halt tests/userprog/halt.result
    if grep -q "PASS" tests/userprog/halt.result
        then let "pass = pass + 1"
    fi
}

test-exit() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   exit \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/exit -a exit --swap-size=4 -- -q -f run exit < /dev/null 2> tests/userprog/exit.errors |tee tests/userprog/exit.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/exit.ck tests/userprog/exit tests/userprog/exit.result
    if grep -q "PASS" tests/userprog/exit.result
        then let "pass = pass + 1"
    fi
}

test-create-normal() 
{    
    let "total = total + 1"  
    echo -e "\n   RUNNING TEST:   create-normal \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/create-normal -a create-normal --swap-size=4 -- -q -f run create-normal < /dev/null 2> tests/userprog/create-normal.errors |tee tests/userprog/create-normal.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/create-normal.ck tests/userprog/create-normal tests/userprog/create-normal.result
    if grep -q "PASS" tests/userprog/create-normal.result
        then let "pass = pass + 1"
    fi
}

test-create-empty() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   create-empty \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/create-empty -a create-empty --swap-size=4 -- -q -f run create-empty < /dev/null 2> tests/userprog/create-empty.errors |tee tests/userprog/create-empty.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/create-empty.ck tests/userprog/create-empty tests/userprog/create-empty.result
    if grep -q "PASS" tests/userprog/create-empty.result
        then let "pass = pass + 1"
    fi
}

test-create-null() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   create-null \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/create-null -a create-null --swap-size=4 -- -q -f run create-null < /dev/null 2> tests/userprog/create-null.errors |tee tests/userprog/create-null.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/create-null.ck tests/userprog/create-null tests/userprog/create-null.result
    if grep -q "PASS" tests/userprog/create-null.result
        then let "pass = pass + 1"
    fi
}

test-create-bad-ptr() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   create-bad-ptr \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/create-bad-ptr -a create-bad-ptr --swap-size=4 -- -q -f run create-bad-ptr < /dev/null 2> tests/userprog/create-bad-ptr.errors |tee tests/userprog/create-bad-ptr.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/create-bad-ptr.ck tests/userprog/create-bad-ptr tests/userprog/create-bad-ptr.result
    if grep -q "PASS" tests/userprog/create-bad-ptr.result
        then let "pass = pass + 1"
    fi
}

test-create-long() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   create-long \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/create-long -a create-long --swap-size=4 -- -q -f run create-long < /dev/null 2> tests/userprog/create-long.errors |tee tests/userprog/create-long.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/create-long.ck tests/userprog/create-long tests/userprog/create-long.result
    if grep -q "PASS" tests/userprog/create-long.result
        then let "pass = pass + 1"
    fi
}

test-create-exists() 
{
    let "total = total + 1"      
    echo -e "\n   RUNNING TEST:   create-exists \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/create-exists -a create-exists --swap-size=4 -- -q -f run create-exists < /dev/null 2> tests/userprog/create-exists.errors |tee tests/userprog/create-exists.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/create-exists.ck tests/userprog/create-exists tests/userprog/create-exists.result
    if grep -q "PASS" tests/userprog/create-exists.result
        then let "pass = pass + 1"
    fi
}

test-create-bound() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   create-bound \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/create-bound -a create-bound --swap-size=4 -- -q -f run create-bound < /dev/null 2> tests/userprog/create-bound.errors |tee tests/userprog/create-bound.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/create-bound.ck tests/userprog/create-bound tests/userprog/create-bound.result
    if grep -q "PASS" tests/userprog/create-bound.result
        then let "pass = pass + 1"
    fi
}

test-open-normal() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   open-normal \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/open-normal -a open-normal -p ../../tests/userprog/sample.txt -a sample.txt --swap-size=4 -- -q -f run open-normal < /dev/null 2> tests/userprog/open-normal.errors |tee tests/userprog/open-normal.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/open-normal.ck tests/userprog/open-normal tests/userprog/open-normal.result
    if grep -q "PASS" tests/userprog/open-normal.result
        then let "pass = pass + 1"
    fi
}

test-open-missing() 
{
    let "total = total + 1"       
    echo -e "\n   RUNNING TEST:   open-missing \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/open-missing -a open-missing --swap-size=4 -- -q -f run open-missing < /dev/null 2> tests/userprog/open-missing.errors |tee tests/userprog/open-missing.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/open-missing.ck tests/userprog/open-missing tests/userprog/open-missing.result
    if grep -q "PASS" tests/userprog/open-missing.result
        then let "pass = pass + 1"
    fi
}

test-open-boundary() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   open-boundary \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/open-boundary -a open-boundary -p ../../tests/userprog/sample.txt -a sample.txt --swap-size=4 -- -q -f run open-boundary < /dev/null 2> tests/userprog/open-boundary.errors |tee tests/userprog/open-boundary.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/open-boundary.ck tests/userprog/open-boundary tests/userprog/open-boundary.result
    if grep -q "PASS" tests/userprog/open-boundary.result
        then let "pass = pass + 1"
    fi
}

test-open-empty() 
{
    let "total = total + 1"      
    echo -e "\n   RUNNING TEST:   open-empty \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/open-empty -a open-empty --swap-size=4 -- -q -f run open-empty < /dev/null 2> tests/userprog/open-empty.errors |tee tests/userprog/open-empty.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/open-empty.ck tests/userprog/open-empty tests/userprog/open-empty.result
    if grep -q "PASS" tests/userprog/open-empty.result
        then let "pass = pass + 1"
    fi
}

test-open-null() 
{
    let "total = total + 1"      
    echo -e "\n   RUNNING TEST:   open-null \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/open-null -a open-null --swap-size=4 -- -q -f run open-null < /dev/null 2> tests/userprog/open-null.errors |tee tests/userprog/open-null.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/open-null.ck tests/userprog/open-null tests/userprog/open-null.result
    if grep -q "PASS" tests/userprog/open-null.result
        then let "pass = pass + 1"
    fi
}

test-open-bad-ptr() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   open-bad-ptr \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/open-bad-ptr -a open-bad-ptr --swap-size=4 -- -q -f run open-bad-ptr < /dev/null 2> tests/userprog/open-bad-ptr.errors |tee tests/userprog/open-bad-ptr.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/open-bad-ptr.ck tests/userprog/open-bad-ptr tests/userprog/open-bad-ptr.result
    if grep -q "PASS" tests/userprog/open-bad-ptr.result
        then let "pass = pass + 1"
    fi
}

test-open-twice() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   open-twice \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/open-twice -a open-twice -p ../../tests/userprog/sample.txt -a sample.txt --swap-size=4 -- -q -f run open-twice < /dev/null 2> tests/userprog/open-twice.errors |tee tests/userprog/open-twice.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/open-twice.ck tests/userprog/open-twice tests/userprog/open-twice.result
    if grep -q "PASS" tests/userprog/open-twice.result
        then let "pass = pass + 1"
    fi
}

test-close-normal() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   close-normal \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/close-normal -a close-normal -p ../../tests/userprog/sample.txt -a sample.txt --swap-size=4 -- -q -f run close-normal < /dev/null 2> tests/userprog/close-normal.errors |tee tests/userprog/close-normal.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/close-normal.ck tests/userprog/close-normal tests/userprog/close-normal.result
    if grep -q "PASS" tests/userprog/close-normal.result
        then let "pass = pass + 1"
    fi
}

test-close-twice() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   close-twice \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/close-twice -a close-twice -p ../../tests/userprog/sample.txt -a sample.txt --swap-size=4 -- -q -f run close-twice < /dev/null 2> tests/userprog/close-twice.errors |tee tests/userprog/close-twice.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/close-twice.ck tests/userprog/close-twice tests/userprog/close-twice.result
    if grep -q "PASS" tests/userprog/close-twice.result
        then let "pass = pass + 1"
    fi
}

test-close-stdin() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   close-stdin \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/close-stdin -a close-stdin --swap-size=4 -- -q -f run close-stdin < /dev/null 2> tests/userprog/close-stdin.errors |tee tests/userprog/close-stdin.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/close-stdin.ck tests/userprog/close-stdin tests/userprog/close-stdin.result
    if grep -q "PASS" tests/userprog/close-stdin.result
        then let "pass = pass + 1"
    fi
}

test-close-stdout() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   close-stdout \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/close-stdout -a close-stdout --swap-size=4 -- -q -f run close-stdout < /dev/null 2> tests/userprog/close-stdout.errors |tee tests/userprog/close-stdout.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/close-stdout.ck tests/userprog/close-stdout tests/userprog/close-stdout.result
    if grep -q "PASS" tests/userprog/close-stdout.result
        then let "pass = pass + 1"
    fi
}

test-close-bad-fd() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   close-bad-fd \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/close-bad-fd -a close-bad-fd --swap-size=4 -- -q -f run close-bad-fd < /dev/null 2> tests/userprog/close-bad-fd.errors |tee tests/userprog/close-bad-fd.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/close-bad-fd.ck tests/userprog/close-bad-fd tests/userprog/close-bad-fd.result
    if grep -q "PASS" tests/userprog/close-bad-fd.result
        then let "pass = pass + 1"
    fi
}

test-read-normal() 
{
    let "total = total + 1"        
    echo -e "\n   RUNNING TEST:   read-normal \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/read-normal -a read-normal -p ../../tests/userprog/sample.txt -a sample.txt --swap-size=4 -- -q -f run read-normal < /dev/null 2> tests/userprog/read-normal.errors |tee tests/userprog/read-normal.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/read-normal.ck tests/userprog/read-normal tests/userprog/read-normal.result
    if grep -q "PASS" tests/userprog/read-normal.result
        then let "pass = pass + 1"
    fi
}

test-read-bad-ptr() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   read-bad-ptr \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/read-bad-ptr -a read-bad-ptr -p ../../tests/userprog/sample.txt -a sample.txt --swap-size=4 -- -q -f run read-bad-ptr < /dev/null 2> tests/userprog/read-bad-ptr.errors |tee tests/userprog/read-bad-ptr.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/read-bad-ptr.ck tests/userprog/read-bad-ptr tests/userprog/read-bad-ptr.result
    if grep -q "PASS" tests/userprog/read-bad-ptr.result
        then let "pass = pass + 1"
    fi
}

test-read-boundary() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   read-boundary \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/read-boundary -a read-boundary -p ../../tests/userprog/sample.txt -a sample.txt --swap-size=4 -- -q -f run read-boundary < /dev/null 2> tests/userprog/read-boundary.errors |tee tests/userprog/read-boundary.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/read-boundary.ck tests/userprog/read-boundary tests/userprog/read-boundary.result
    if grep -q "PASS" tests/userprog/read-boundary.result
        then let "pass = pass + 1"
    fi
}

test-read-zero() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   read-zero \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/read-zero -a read-zero -p ../../tests/userprog/sample.txt -a sample.txt --swap-size=4 -- -q -f run read-zero < /dev/null 2> tests/userprog/read-zero.errors |tee tests/userprog/read-zero.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/read-zero.ck tests/userprog/read-zero tests/userprog/read-zero.result
    if grep -q "PASS" tests/userprog/read-zero.result
        then let "pass = pass + 1"
    fi
}

test-read-stdout() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   read-stdout \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/read-stdout -a read-stdout --swap-size=4 -- -q -f run read-stdout < /dev/null 2> tests/userprog/read-stdout.errors |tee tests/userprog/read-stdout.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/read-stdout.ck tests/userprog/read-stdout tests/userprog/read-stdout.result
    if grep -q "PASS" tests/userprog/read-stdout.result
        then let "pass = pass + 1"
    fi
}

test-read-bad-fd() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   read-bad-fd \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/read-bad-fd -a read-bad-fd --swap-size=4 -- -q -f run read-bad-fd < /dev/null 2> tests/userprog/read-bad-fd.errors |tee tests/userprog/read-bad-fd.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/read-bad-fd.ck tests/userprog/read-bad-fd tests/userprog/read-bad-fd.result
    if grep -q "PASS" tests/userprog/read-bad-fd.result
        then let "pass = pass + 1"
    fi
}

test-write-normal() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   write-normal \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/write-normal -a write-normal -p ../../tests/userprog/sample.txt -a sample.txt --swap-size=4 -- -q -f run write-normal < /dev/null 2> tests/userprog/write-normal.errors |tee tests/userprog/write-normal.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/write-normal.ck tests/userprog/write-normal tests/userprog/write-normal.result
    if grep -q "PASS" tests/userprog/write-normal.result
        then let "pass = pass + 1"
    fi
}

test-write-bad-ptr() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   write-bad-ptr \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/write-bad-ptr -a write-bad-ptr -p ../../tests/userprog/sample.txt -a sample.txt --swap-size=4 -- -q -f run write-bad-ptr < /dev/null 2> tests/userprog/write-bad-ptr.errors |tee tests/userprog/write-bad-ptr.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/write-bad-ptr.ck tests/userprog/write-bad-ptr tests/userprog/write-bad-ptr.result
    if grep -q "PASS" tests/userprog/write-bad-ptr.result
        then let "pass = pass + 1"
    fi
}

test-write-boundary() 
{
    let "total = total + 1"      
    echo -e "\n   RUNNING TEST:   write-boundary \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/write-boundary -a write-boundary -p ../../tests/userprog/sample.txt -a sample.txt --swap-size=4 -- -q -f run write-boundary < /dev/null 2> tests/userprog/write-boundary.errors |tee tests/userprog/write-boundary.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/write-boundary.ck tests/userprog/write-boundary tests/userprog/write-boundary.result
    if grep -q "PASS" tests/userprog/write-boundary.result
        then let "pass = pass + 1"
    fi
}

test-write-zero() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   write-zero \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/write-zero -a write-zero -p ../../tests/userprog/sample.txt -a sample.txt --swap-size=4 -- -q -f run write-zero < /dev/null 2> tests/userprog/write-zero.errors |tee tests/userprog/write-zero.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/write-zero.ck tests/userprog/write-zero tests/userprog/write-zero.result
    if grep -q "PASS" tests/userprog/write-zero.result
        then let "pass = pass + 1"
    fi
}

test-write-stdin() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   write-stdin \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/write-stdin -a write-stdin --swap-size=4 -- -q -f run write-stdin < /dev/null 2> tests/userprog/write-stdin.errors |tee tests/userprog/write-stdin.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/write-stdin.ck tests/userprog/write-stdin tests/userprog/write-stdin.result
    if grep -q "PASS" tests/userprog/write-stdin.result
        then let "pass = pass + 1"
    fi
}

test-write-bad-fd() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   write-bad-fd \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/write-bad-fd -a write-bad-fd --swap-size=4 -- -q -f run write-bad-fd < /dev/null 2> tests/userprog/write-bad-fd.errors |tee tests/userprog/write-bad-fd.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/write-bad-fd.ck tests/userprog/write-bad-fd tests/userprog/write-bad-fd.result
    if grep -q "PASS" tests/userprog/write-bad-fd.result
        then let "pass = pass + 1"
    fi
}

test-exec-once() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   exec-once \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/exec-once -a exec-once -p tests/userprog/child-simple -a child-simple --swap-size=4 -- -q -f run exec-once < /dev/null 2> tests/userprog/exec-once.errors |tee tests/userprog/exec-once.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/exec-once.ck tests/userprog/exec-once tests/userprog/exec-once.result
    if grep -q "PASS" tests/userprog/exec-once.result
        then let "pass = pass + 1"
    fi
}

test-exec-arg() 
{
    let "total = total + 1"       
    echo -e "\n   RUNNING TEST:   exec-arg \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/exec-arg -a exec-arg -p tests/userprog/child-args -a child-args --swap-size=4 -- -q -f run exec-arg < /dev/null 2> tests/userprog/exec-arg.errors |tee tests/userprog/exec-arg.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/exec-arg.ck tests/userprog/exec-arg tests/userprog/exec-arg.result
    if grep -q "PASS" tests/userprog/exec-arg.result
        then let "pass = pass + 1"
    fi
}

test-exec-multiple() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   exec-multiple \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/exec-multiple -a exec-multiple -p tests/userprog/child-simple -a child-simple --swap-size=4 -- -q -f run exec-multiple < /dev/null 2> tests/userprog/exec-multiple.errors |tee tests/userprog/exec-multiple.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/exec-multiple.ck tests/userprog/exec-multiple tests/userprog/exec-multiple.result
    if grep -q "PASS" tests/userprog/exec-multiple.result
        then let "pass = pass + 1"
    fi
}

test-exec-missing() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   exec-missing \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/exec-missing -a exec-missing --swap-size=4 -- -q -f run exec-missing < /dev/null 2> tests/userprog/exec-missing.errors |tee tests/userprog/exec-missing.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/exec-missing.ck tests/userprog/exec-missing tests/userprog/exec-missing.result
    if grep -q "PASS" tests/userprog/exec-missing.result
        then let "pass = pass + 1"
    fi
}

test-exec-bad-ptr() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   exec-bad-ptr \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/exec-bad-ptr -a exec-bad-ptr --swap-size=4 -- -q -f run exec-bad-ptr < /dev/null 2> tests/userprog/exec-bad-ptr.errors |tee tests/userprog/exec-bad-ptr.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/exec-bad-ptr.ck tests/userprog/exec-bad-ptr tests/userprog/exec-bad-ptr.result
    if grep -q "PASS" tests/userprog/exec-bad-ptr.result
        then let "pass = pass + 1"
    fi
}

test-wait-simple() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   wait-simple \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/wait-simple -a wait-simple -p tests/userprog/child-simple -a child-simple --swap-size=4 -- -q -f run wait-simple < /dev/null 2> tests/userprog/wait-simple.errors |tee tests/userprog/wait-simple.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/wait-simple.ck tests/userprog/wait-simple tests/userprog/wait-simple.result
    if grep -q "PASS" tests/userprog/wait-simple.result
        then let "pass = pass + 1"
    fi
}

test-wait-twice() 
{
    let "total = total + 1"      
    echo -e "\n   RUNNING TEST:   wait-twice \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/wait-twice -a wait-twice -p tests/userprog/child-simple -a child-simple --swap-size=4 -- -q -f run wait-twice < /dev/null 2> tests/userprog/wait-twice.errors |tee tests/userprog/wait-twice.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/wait-twice.ck tests/userprog/wait-twice tests/userprog/wait-twice.result
    if grep -q "PASS" tests/userprog/wait-twice.result
        then let "pass = pass + 1"
    fi
}

test-wait-killed() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   wait-killed \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/wait-killed -a wait-killed -p tests/userprog/child-bad -a child-bad --swap-size=4 -- -q -f run wait-killed < /dev/null 2> tests/userprog/wait-killed.errors |tee tests/userprog/wait-killed.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/wait-killed.ck tests/userprog/wait-killed tests/userprog/wait-killed.result
    if grep -q "PASS" tests/userprog/wait-killed.result
        then let "pass = pass + 1"
    fi
}

test-wait-bad-pid() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   wait-bad-pid \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/wait-bad-pid -a wait-bad-pid --swap-size=4 -- -q -f run wait-bad-pid < /dev/null 2> tests/userprog/wait-bad-pid.errors |tee tests/userprog/wait-bad-pid.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/wait-bad-pid.ck tests/userprog/wait-bad-pid tests/userprog/wait-bad-pid.result
    if grep -q "PASS" tests/userprog/wait-bad-pid.result
        then let "pass = pass + 1"
    fi
}

test-multi-recurse() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   multi-recurse \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/multi-recurse -a multi-recurse --swap-size=4 -- -q -f run 'multi-recurse 15' < /dev/null 2> tests/userprog/multi-recurse.errors |tee tests/userprog/multi-recurse.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/multi-recurse.ck tests/userprog/multi-recurse tests/userprog/multi-recurse.result
    if grep -q "PASS" tests/userprog/multi-recurse.result
        then let "pass = pass + 1"
    fi
}

test-multi-child-fd() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   multi-child-fd \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/multi-child-fd -a multi-child-fd -p ../../tests/userprog/sample.txt -a sample.txt -p tests/userprog/child-close -a child-close --swap-size=4 -- -q -f run multi-child-fd < /dev/null 2> tests/userprog/multi-child-fd.errors |tee tests/userprog/multi-child-fd.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/multi-child-fd.ck tests/userprog/multi-child-fd tests/userprog/multi-child-fd.result
    if grep -q "PASS" tests/userprog/multi-child-fd.result
        then let "pass = pass + 1"
    fi
}

test-rox-simple() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   rox-simple \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/rox-simple -a rox-simple --swap-size=4 -- -q -f run rox-simple < /dev/null 2> tests/userprog/rox-simple.errors |tee tests/userprog/rox-simple.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/rox-simple.ck tests/userprog/rox-simple tests/userprog/rox-simple.result
    if grep -q "PASS" tests/userprog/rox-simple.result
        then let "pass = pass + 1"
    fi
}

test-rox-child() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   rox-child \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/rox-child -a rox-child -p tests/userprog/child-rox -a child-rox --swap-size=4 -- -q -f run rox-child < /dev/null 2> tests/userprog/rox-child.errors |tee tests/userprog/rox-child.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/rox-child.ck tests/userprog/rox-child tests/userprog/rox-child.result
    if grep -q "PASS" tests/userprog/rox-child.result
        then let "pass = pass + 1"
    fi
}

test-rox-multichild() 
{
    let "total = total + 1"        
    echo -e "\n   RUNNING TEST:   rox-multichild \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/rox-multichild -a rox-multichild -p tests/userprog/child-rox -a child-rox --swap-size=4 -- -q -f run rox-multichild < /dev/null 2> tests/userprog/rox-multichild.errors |tee tests/userprog/rox-multichild.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/rox-multichild.ck tests/userprog/rox-multichild tests/userprog/rox-multichild.result
    if grep -q "PASS" tests/userprog/rox-multichild.result
        then let "pass = pass + 1"
    fi
}

test-bad-read() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   bad-read \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/bad-read -a bad-read --swap-size=4 -- -q -f run bad-read < /dev/null 2> tests/userprog/bad-read.errors |tee tests/userprog/bad-read.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/bad-read.ck tests/userprog/bad-read tests/userprog/bad-read.result
    if grep -q "PASS" tests/userprog/bad-read.result
        then let "pass = pass + 1"
    fi
}

test-bad-write() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   bad-write \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/bad-write -a bad-write --swap-size=4 -- -q -f run bad-write < /dev/null 2> tests/userprog/bad-write.errors |tee tests/userprog/bad-write.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/bad-write.ck tests/userprog/bad-write tests/userprog/bad-write.result
    if grep -q "PASS" tests/userprog/bad-write.result
        then let "pass = pass + 1"
    fi
}

test-bad-read2() 
{
    let "total = total + 1"      
    echo -e "\n   RUNNING TEST:   bad-read2 \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/bad-read2 -a bad-read2 --swap-size=4 -- -q -f run bad-read2 < /dev/null 2> tests/userprog/bad-read2.errors |tee tests/userprog/bad-read2.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/bad-read2.ck tests/userprog/bad-read2 tests/userprog/bad-read2.result
    if grep -q "PASS" tests/userprog/bad-read2.result
        then let "pass = pass + 1"
    fi
}

test-bad-write2() 
{
    let "total = total + 1"      
    echo -e "\n   RUNNING TEST:   bad-write2 \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/bad-write2 -a bad-write2 --swap-size=4 -- -q -f run bad-write2 < /dev/null 2> tests/userprog/bad-write2.errors |tee tests/userprog/bad-write2.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/bad-write2.ck tests/userprog/bad-write2 tests/userprog/bad-write2.result
    if grep -q "PASS" tests/userprog/bad-write2.result
        then let "pass = pass + 1"
    fi
}

test-bad-jump() 
{
    let "total = total + 1"      
    echo -e "\n   RUNNING TEST:   bad-jump \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/bad-jump -a bad-jump --swap-size=4 -- -q -f run bad-jump < /dev/null 2> tests/userprog/bad-jump.errors |tee tests/userprog/bad-jump.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/bad-jump.ck tests/userprog/bad-jump tests/userprog/bad-jump.result
    if grep -q "PASS" tests/userprog/bad-jump.result
        then let "pass = pass + 1"
    fi
}

test-bad-jump2() 
{
    let "total = total + 1"      
    echo -e "\n   RUNNING TEST:   bad-jump2 \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/userprog/bad-jump2 -a bad-jump2 --swap-size=4 -- -q -f run bad-jump2 < /dev/null 2> tests/userprog/bad-jump2.errors |tee tests/userprog/bad-jump2.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/userprog/bad-jump2.ck tests/userprog/bad-jump2 tests/userprog/bad-jump2.result
    if grep -q "PASS" tests/userprog/bad-jump2.result
        then let "pass = pass + 1"
    fi
}

test-lg-create() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   lg-create \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/filesys/base/lg-create -a lg-create --swap-size=4 -- -q -f run lg-create < /dev/null 2> tests/filesys/base/lg-create.errors |tee tests/filesys/base/lg-create.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/filesys/base/lg-create.ck tests/filesys/base/lg-create tests/filesys/base/lg-create.result
    if grep -q "PASS" tests/filesys/base/lg-create.result
        then let "pass = pass + 1"
    fi
}

test-lg-full() 
{
    let "total = total + 1"      
    echo -e "\n   RUNNING TEST:   lg-full \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/filesys/base/lg-full -a lg-full --swap-size=4 -- -q -f run lg-full < /dev/null 2> tests/filesys/base/lg-full.errors |tee tests/filesys/base/lg-full.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/filesys/base/lg-full.ck tests/filesys/base/lg-full tests/filesys/base/lg-full.result
    if grep -q "PASS" tests/filesys/base/lg-full.result
        then let "pass = pass + 1"
    fi
}

test-lg-random() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   lg-random \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/filesys/base/lg-random -a lg-random --swap-size=4 -- -q -f run lg-random < /dev/null 2> tests/filesys/base/lg-random.errors |tee tests/filesys/base/lg-random.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/filesys/base/lg-random.ck tests/filesys/base/lg-random tests/filesys/base/lg-random.result
    if grep -q "PASS" tests/filesys/base/lg-random.result
        then let "pass = pass + 1"
    fi
}

test-lg-seq-block() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   lg-seq-block \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/filesys/base/lg-seq-block -a lg-seq-block --swap-size=4 -- -q -f run lg-seq-block < /dev/null 2> tests/filesys/base/lg-seq-block.errors |tee tests/filesys/base/lg-seq-block.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/filesys/base/lg-seq-block.ck tests/filesys/base/lg-seq-block tests/filesys/base/lg-seq-block.result
    if grep -q "PASS" tests/filesys/base/lg-seq-block.result
        then let "pass = pass + 1"
    fi
}

test-lg-seq-random() 
{
    let "total = total + 1"    
    echo -e "\n   RUNNING TEST:   lg-seq-random \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/filesys/base/lg-seq-random -a lg-seq-random --swap-size=4 -- -q -f run lg-seq-random < /dev/null 2> tests/filesys/base/lg-seq-random.errors |tee tests/filesys/base/lg-seq-random.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/filesys/base/lg-seq-random.ck tests/filesys/base/lg-seq-random tests/filesys/base/lg-seq-random.result
    if grep -q "PASS" tests/filesys/base/lg-seq-random.result
        then let "pass = pass + 1"
    fi
}

test-sm-create() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   sm-create \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/filesys/base/sm-create -a sm-create --swap-size=4 -- -q -f run sm-create < /dev/null 2> tests/filesys/base/sm-create.errors |tee tests/filesys/base/sm-create.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/filesys/base/sm-create.ck tests/filesys/base/sm-create tests/filesys/base/sm-create.result
    if grep -q "PASS" tests/filesys/base/sm-create.result
        then let "pass = pass + 1"
    fi
}

test-sm-full() 
{
    let "total = total + 1"      
    echo -e "\n   RUNNING TEST:   sm-full \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/filesys/base/sm-full -a sm-full --swap-size=4 -- -q -f run sm-full < /dev/null 2> tests/filesys/base/sm-full.errors |tee tests/filesys/base/sm-full.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/filesys/base/sm-full.ck tests/filesys/base/sm-full tests/filesys/base/sm-full.result
    if grep -q "PASS" tests/filesys/base/sm-full.result
        then let "pass = pass + 1"
    fi
}

test-sm-random() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   sm-random \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/filesys/base/sm-random -a sm-random --swap-size=4 -- -q -f run sm-random < /dev/null 2> tests/filesys/base/sm-random.errors |tee tests/filesys/base/sm-random.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/filesys/base/sm-random.ck tests/filesys/base/sm-random tests/filesys/base/sm-random.result
    if grep -q "PASS" tests/filesys/base/sm-random.result
        then let "pass = pass + 1"
    fi
}

test-sm-seq-block() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   sm-seq-block \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/filesys/base/sm-seq-block -a sm-seq-block --swap-size=4 -- -q -f run sm-seq-block < /dev/null 2> tests/filesys/base/sm-seq-block.errors |tee tests/filesys/base/sm-seq-block.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/filesys/base/sm-seq-block.ck tests/filesys/base/sm-seq-block tests/filesys/base/sm-seq-block.result
    if grep -q "PASS" tests/filesys/base/sm-seq-block.result
        then let "pass = pass + 1"
    fi
}

test-sm-seq-random() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   sm-seq-random \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/filesys/base/sm-seq-random -a sm-seq-random --swap-size=4 -- -q -f run sm-seq-random < /dev/null 2> tests/filesys/base/sm-seq-random.errors |tee tests/filesys/base/sm-seq-random.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/filesys/base/sm-seq-random.ck tests/filesys/base/sm-seq-random tests/filesys/base/sm-seq-random.result
    if grep -q "PASS" tests/filesys/base/sm-seq-random.result
        then let "pass = pass + 1"
    fi
}

test-syn-read() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   syn-read \n"
    pintos -v -k -T 300 --filesys-size=2 -p tests/filesys/base/syn-read -a syn-read -p tests/filesys/base/child-syn-read -a child-syn-read --swap-size=4 -- -q -f run syn-read < /dev/null 2> tests/filesys/base/syn-read.errors |tee tests/filesys/base/syn-read.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/filesys/base/syn-read.ck tests/filesys/base/syn-read tests/filesys/base/syn-read.result
    if grep -q "PASS" tests/filesys/base/syn-read.result
        then let "pass = pass + 1"
    fi
}

test-syn-remove() 
{
    let "total = total + 1"     
    echo -e "\n   RUNNING TEST:   syn-remove \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/filesys/base/syn-remove -a syn-remove --swap-size=4 -- -q -f run syn-remove < /dev/null 2> tests/filesys/base/syn-remove.errors |tee tests/filesys/base/syn-remove.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/filesys/base/syn-remove.ck tests/filesys/base/syn-remove tests/filesys/base/syn-remove.result
    if grep -q "PASS" tests/filesys/base/syn-remove.result
        then let "pass = pass + 1"
    fi
}

test-syn-write() 
{
    let "total = total + 1"      
    echo -e "\n   RUNNING TEST:   syn-write \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/filesys/base/syn-write -a syn-write -p tests/filesys/base/child-syn-wrt -a child-syn-wrt --swap-size=4 -- -q -f run syn-write < /dev/null 2> tests/filesys/base/syn-write.errors |tee tests/filesys/base/syn-write.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/filesys/base/syn-write.ck tests/filesys/base/syn-write tests/filesys/base/syn-write.result
    if grep -q "PASS" tests/filesys/base/syn-write.result
        then let "pass = pass + 1"
    fi
}

test-pt-grow-stack()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   pt-grow-stack \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/pt-grow-stack -a pt-grow-stack --swap-size=4 -- -q -f run pt-grow-stack < /dev/null 2> tests/vm/pt-grow-stack.errors |tee tests/vm/pt-grow-stack.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/pt-grow-stack.ck tests/vm/pt-grow-stack tests/vm/pt-grow-stack.result
    if grep -q "PASS" tests/vm/pt-grow-stack.result
        then let "pass = pass + 1"
    fi
}

test-pt-grow-pusha()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   pt-grow-pusha \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/pt-grow-pusha -a pt-grow-pusha --swap-size=4 -- -q -f run pt-grow-pusha < /dev/null 2> tests/vm/pt-grow-pusha.errors |tee tests/vm/pt-grow-pusha.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/pt-grow-pusha.ck tests/vm/pt-grow-pusha tests/vm/pt-grow-pusha.result
    if grep -q "PASS" tests/vm/pt-grow-pusha.result
        then let "pass = pass + 1"
    fi
}

test-pt-grow-bad()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   pt-grow-bad \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/pt-grow-bad -a pt-grow-bad --swap-size=4 -- -q -f run pt-grow-bad < /dev/null 2> tests/vm/pt-grow-bad.errors |tee tests/vm/pt-grow-bad.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/pt-grow-bad.ck tests/vm/pt-grow-bad tests/vm/pt-grow-bad.result
    if grep -q "PASS" tests/vm/pt-grow-bad.result
        then let "pass = pass + 1"
    fi
}

test-pt-big-stk-obj()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   pt-big-stk-obj \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/pt-big-stk-obj -a pt-big-stk-obj --swap-size=4 -- -q -f run pt-big-stk-obj < /dev/null 2> tests/vm/pt-big-stk-obj.errors |tee tests/vm/pt-big-stk-obj.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/pt-big-stk-obj.ck tests/vm/pt-big-stk-obj tests/vm/pt-big-stk-obj.result
    if grep -q "PASS" tests/vm/pt-big-stk-obj.result
        then let "pass = pass + 1"
    fi
}

test-pt-bad-addr()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   pt-bad-addr \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/pt-bad-addr -a pt-bad-addr --swap-size=4 -- -q -f run pt-bad-addr < /dev/null 2> tests/vm/pt-bad-addr.errors |tee tests/vm/pt-bad-addr.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/pt-bad-addr.ck tests/vm/pt-bad-addr tests/vm/pt-bad-addr.result
    if grep -q "PASS" tests/vm/pt-bad-addr.result
        then let "pass = pass + 1"
    fi
}

test-pt-bad-read()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   pt-bad-read \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/pt-bad-read -a pt-bad-read -p ../../tests/vm/sample.txt -a sample.txt --swap-size=4 -- -q -f run pt-bad-read < /dev/null 2> tests/vm/pt-bad-read.errors |tee tests/vm/pt-bad-read.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/pt-bad-read.ck tests/vm/pt-bad-read tests/vm/pt-bad-read.result
    if grep -q "PASS" tests/vm/pt-bad-read.result
        then let "pass = pass + 1"
    fi
}

test-pt-write-code()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   pt-write-code \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/pt-write-code -a pt-write-code --swap-size=4 -- -q -f run pt-write-code < /dev/null 2> tests/vm/pt-write-code.errors |tee tests/vm/pt-write-code.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/pt-write-code.ck tests/vm/pt-write-code tests/vm/pt-write-code.result
    if grep -q "PASS" tests/vm/pt-write-code.result
        then let "pass = pass + 1"
    fi
}

test-pt-write-code2()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   pt-write-code2 \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/pt-write-code2 -a pt-write-code2 -p ../../tests/vm/sample.txt -a sample.txt --swap-size=4 -- -q -f run pt-write-code2 < /dev/null 2> tests/vm/pt-write-code2.errors |tee tests/vm/pt-write-code2.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/pt-write-code2.ck tests/vm/pt-write-code2 tests/vm/pt-write-code2.result
    if grep -q "PASS" tests/vm/pt-write-code2.result
        then let "pass = pass + 1"
    fi
}

test-pt-grow-stk-sc()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   pt-grow-stk-sc \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/pt-grow-stk-sc -a pt-grow-stk-sc --swap-size=4 -- -q -f run pt-grow-stk-sc < /dev/null 2> tests/vm/pt-grow-stk-sc.errors |tee tests/vm/pt-grow-stk-sc.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/pt-grow-stk-sc.ck tests/vm/pt-grow-stk-sc tests/vm/pt-grow-stk-sc.result
    if grep -q "PASS" tests/vm/pt-grow-stk-sc.result
        then let "pass = pass + 1"
    fi
}

test-page-linear()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   page-linear \n"
    pintos -v -k -T 300 --filesys-size=2 -p tests/vm/page-linear -a page-linear --swap-size=4 -- -q -f run page-linear < /dev/null 2> tests/vm/page-linear.errors |tee tests/vm/page-linear.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/page-linear.ck tests/vm/page-linear tests/vm/page-linear.result
    if grep -q "PASS" tests/vm/page-linear.result
        then let "pass = pass + 1"
    fi
}

test-page-parallel()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   page-parallel \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/page-parallel -a page-parallel -p tests/vm/child-linear -a child-linear --swap-size=4 -- -q -f run page-parallel < /dev/null 2> tests/vm/page-parallel.errors |tee tests/vm/page-parallel.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/page-parallel.ck tests/vm/page-parallel tests/vm/page-parallel.result
    if grep -q "PASS" tests/vm/page-parallel.result
        then let "pass = pass + 1"
    fi
}

test-page-merge-seq()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   page-merge-seq \n"
    pintos -v -k -T 600 --filesys-size=2 -p tests/vm/page-merge-seq -a page-merge-seq -p tests/vm/child-sort -a child-sort --swap-size=4 -- -q -f run page-merge-seq < /dev/null 2> tests/vm/page-merge-seq.errors |tee tests/vm/page-merge-seq.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/page-merge-seq.ck tests/vm/page-merge-seq tests/vm/page-merge-seq.result
    if grep -q "PASS" tests/vm/page-merge-seq.result
        then let "pass = pass + 1"
    fi
}

test-page-merge-par()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   page-merge-par \n"
    pintos -v -k -T 600 --filesys-size=2 -p tests/vm/page-merge-par -a page-merge-par -p tests/vm/child-sort -a child-sort --swap-size=4 -- -q -f run page-merge-par < /dev/null 2> tests/vm/page-merge-par.errors |tee tests/vm/page-merge-par.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/page-merge-par.ck tests/vm/page-merge-par tests/vm/page-merge-par.result
    if grep -q "PASS" tests/vm/page-merge-par.result
        then let "pass = pass + 1"
    fi
}

test-page-merge-stk()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   page-merge-stk \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/page-merge-stk -a page-merge-stk -p tests/vm/child-qsort -a child-qsort --swap-size=4 -- -q -f run page-merge-stk < /dev/null 2> tests/vm/page-merge-stk.errors |tee tests/vm/page-merge-stk.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/page-merge-stk.ck tests/vm/page-merge-stk tests/vm/page-merge-stk.result
    if grep -q "PASS" tests/vm/page-merge-stk.result
        then let "pass = pass + 1"
    fi
}

test-page-merge-mm()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   page-merge-mm \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/page-merge-mm -a page-merge-mm -p tests/vm/child-qsort-mm -a child-qsort-mm --swap-size=4 -- -q -f run page-merge-mm < /dev/null 2> tests/vm/page-merge-mm.errors |tee tests/vm/page-merge-mm.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/page-merge-mm.ck tests/vm/page-merge-mm tests/vm/page-merge-mm.result
    if grep -q "PASS" tests/vm/page-merge-mm.result
        then let "pass = pass + 1"
    fi
}

test-page-shuffle()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   page-shuffle \n"
    pintos -v -k -T 600 --filesys-size=2 -p tests/vm/page-shuffle -a page-shuffle --swap-size=4 -- -q -f run page-shuffle < /dev/null 2> tests/vm/page-shuffle.errors |tee tests/vm/page-shuffle.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/page-shuffle.ck tests/vm/page-shuffle tests/vm/page-shuffle.result
    if grep -q "PASS" tests/vm/page-shuffle.result
        then let "pass = pass + 1"
    fi
}

test-mmap-read()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-read \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-read -a mmap-read -p ../../tests/vm/sample.txt -a sample.txt --swap-size=4 -- -q -f run mmap-read < /dev/null 2> tests/vm/mmap-read.errors |tee tests/vm/mmap-read.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-read.ck tests/vm/mmap-read tests/vm/mmap-read.result
    if grep -q "PASS" tests/vm/mmap-read.result
        then let "pass = pass + 1"
    fi
}

test-mmap-close()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-close \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-close -a mmap-close -p ../../tests/vm/sample.txt -a sample.txt --swap-size=4 -- -q -f run mmap-close < /dev/null 2> tests/vm/mmap-close.errors |tee tests/vm/mmap-close.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-close.ck tests/vm/mmap-close tests/vm/mmap-close.result
    if grep -q "PASS" tests/vm/mmap-close.result
        then let "pass = pass + 1"
    fi
}

test-mmap-unmap()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-unmap \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-unmap -a mmap-unmap -p ../../tests/vm/sample.txt -a sample.txt --swap-size=4 -- -q -f run mmap-unmap < /dev/null 2> tests/vm/mmap-unmap.errors |tee tests/vm/mmap-unmap.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-unmap.ck tests/vm/mmap-unmap tests/vm/mmap-unmap.result
    if grep -q "PASS" tests/vm/mmap-unmap.result
        then let "pass = pass + 1"
    fi
}

test-mmap-overlap()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-overlap \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-overlap -a mmap-overlap -p tests/vm/zeros -a zeros --swap-size=4 -- -q -f run mmap-overlap < /dev/null 2> tests/vm/mmap-overlap.errors |tee tests/vm/mmap-overlap.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-overlap.ck tests/vm/mmap-overlap tests/vm/mmap-overlap.result
    if grep -q "PASS" tests/vm/mmap-overlap.result
        then let "pass = pass + 1"
    fi
}

test-mmap-twice()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-twice \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-twice -a mmap-twice -p ../../tests/vm/sample.txt -a sample.txt --swap-size=4 -- -q -f run mmap-twice < /dev/null 2> tests/vm/mmap-twice.errors |tee tests/vm/mmap-twice.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-twice.ck tests/vm/mmap-twice tests/vm/mmap-twice.result
    if grep -q "PASS" tests/vm/mmap-twice.result
        then let "pass = pass + 1"
    fi
}

test-mmap-write()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-write \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-write -a mmap-write --swap-size=4 -- -q -f run mmap-write < /dev/null 2> tests/vm/mmap-write.errors |tee tests/vm/mmap-write.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-write.ck tests/vm/mmap-write tests/vm/mmap-write.result
    if grep -q "PASS" tests/vm/mmap-write.result
        then let "pass = pass + 1"
    fi
}

test-mmap-exit()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-exit \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-exit -a mmap-exit -p tests/vm/child-mm-wrt -a child-mm-wrt --swap-size=4 -- -q -f run mmap-exit < /dev/null 2> tests/vm/mmap-exit.errors |tee tests/vm/mmap-exit.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-exit.ck tests/vm/mmap-exit tests/vm/mmap-exit.result
    if grep -q "PASS" tests/vm/mmap-exit.result
        then let "pass = pass + 1"
    fi
}

test-mmap-shuffle()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-shuffle \n"
    pintos -v -k -T 600 --filesys-size=2 -p tests/vm/mmap-shuffle -a mmap-shuffle --swap-size=4 -- -q -f run mmap-shuffle < /dev/null 2> tests/vm/mmap-shuffle.errors |tee tests/vm/mmap-shuffle.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-shuffle.ck tests/vm/mmap-shuffle tests/vm/mmap-shuffle.result
    if grep -q "PASS" tests/vm/mmap-shuffle.result
        then let "pass = pass + 1"
    fi
}

test-mmap-bad-fd()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-bad-fd \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-bad-fd -a mmap-bad-fd --swap-size=4 -- -q -f run mmap-bad-fd < /dev/null 2> tests/vm/mmap-bad-fd.errors |tee tests/vm/mmap-bad-fd.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-bad-fd.ck tests/vm/mmap-bad-fd tests/vm/mmap-bad-fd.result
    if grep -q "PASS" tests/vm/mmap-bad-fd.result
        then let "pass = pass + 1"
    fi
}

test-mmap-clean()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-clean \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-clean -a mmap-clean -p ../../tests/vm/sample.txt -a sample.txt --swap-size=4 -- -q -f run mmap-clean < /dev/null 2> tests/vm/mmap-clean.errors |tee tests/vm/mmap-clean.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-clean.ck tests/vm/mmap-clean tests/vm/mmap-clean.result
    if grep -q "PASS" tests/vm/mmap-clean.result
        then let "pass = pass + 1"
    fi
}

test-mmap-inherit()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-inherit \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-inherit -a mmap-inherit -p ../../tests/vm/sample.txt -a sample.txt -p tests/vm/child-inherit -a child-inherit --swap-size=4 -- -q -f run mmap-inherit < /dev/null 2> tests/vm/mmap-inherit.errors |tee tests/vm/mmap-inherit.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-inherit.ck tests/vm/mmap-inherit tests/vm/mmap-inherit.result
    if grep -q "PASS" tests/vm/mmap-inherit.result
        then let "pass = pass + 1"
    fi
}

test-mmap-misalign()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-misalign \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-misalign -a mmap-misalign -p ../../tests/vm/sample.txt -a sample.txt --swap-size=4 -- -q -f run mmap-misalign < /dev/null 2> tests/vm/mmap-misalign.errors |tee tests/vm/mmap-misalign.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-misalign.ck tests/vm/mmap-misalign tests/vm/mmap-misalign.result
    if grep -q "PASS" tests/vm/mmap-misalign.result
        then let "pass = pass + 1"
    fi
}

test-mmap-null()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-null \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-null -a mmap-null -p ../../tests/vm/sample.txt -a sample.txt --swap-size=4 -- -q -f run mmap-null < /dev/null 2> tests/vm/mmap-null.errors |tee tests/vm/mmap-null.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-null.ck tests/vm/mmap-null tests/vm/mmap-null.result
    if grep -q "PASS" tests/vm/mmap-null.result
        then let "pass = pass + 1"
    fi
}

test-mmap-over-code()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-over-code \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-over-code -a mmap-over-code -p ../../tests/vm/sample.txt -a sample.txt --swap-size=4 -- -q -f run mmap-over-code < /dev/null 2> tests/vm/mmap-over-code.errors |tee tests/vm/mmap-over-code.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-over-code.ck tests/vm/mmap-over-code tests/vm/mmap-over-code.result
    if grep -q "PASS" tests/vm/mmap-over-code.result
        then let "pass = pass + 1"
    fi
}

test-mmap-over-data()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-over-data \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-over-data -a mmap-over-data -p ../../tests/vm/sample.txt -a sample.txt --swap-size=4 -- -q -f run mmap-over-data < /dev/null 2> tests/vm/mmap-over-data.errors |tee tests/vm/mmap-over-data.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-over-data.ck tests/vm/mmap-over-data tests/vm/mmap-over-data.result
    if grep -q "PASS" tests/vm/mmap-over-data.result
        then let "pass = pass + 1"
    fi
}

test-mmap-over-stk()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-over-stk \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-over-stk -a mmap-over-stk -p ../../tests/vm/sample.txt -a sample.txt --swap-size=4 -- -q -f run mmap-over-stk < /dev/null 2> tests/vm/mmap-over-stk.errors |tee tests/vm/mmap-over-stk.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-over-stk.ck tests/vm/mmap-over-stk tests/vm/mmap-over-stk.result
    if grep -q "PASS" tests/vm/mmap-over-stk.result
        then let "pass = pass + 1"
    fi
}

test-mmap-remove()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-remove \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-remove -a mmap-remove -p ../../tests/vm/sample.txt -a sample.txt --swap-size=4 -- -q -f run mmap-remove < /dev/null 2> tests/vm/mmap-remove.errors |tee tests/vm/mmap-remove.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-remove.ck tests/vm/mmap-remove tests/vm/mmap-remove.result
    if grep -q "PASS" tests/vm/mmap-remove.result
        then let "pass = pass + 1"
    fi
}

test-mmap-zero()
{
    let "total = total + 1"
    echo -e "\n   RUNNING TEST:   mmap-zero \n"
    pintos -v -k -T 60 --filesys-size=2 -p tests/vm/mmap-zero -a mmap-zero --swap-size=4 -- -q -f run mmap-zero < /dev/null 2> tests/vm/mmap-zero.errors |tee tests/vm/mmap-zero.output
    echo -e "\n   RESULT: \n"
    perl -I../.. ../../tests/vm/mmap-zero.ck tests/vm/mmap-zero tests/vm/mmap-zero.result
    if grep -q "PASS" tests/vm/mmap-zero.result
        then let "pass = pass + 1"
    fi
}


main "$@"
