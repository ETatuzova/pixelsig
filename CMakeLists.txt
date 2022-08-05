# CMakeLists files in this project can
# refer to the root source directory of the project as ${HELLO_SOURCE_DIR} and
# to the root binary directory of the project as ${HELLO_BINARY_DIR}.
cmake_minimum_required (VERSION 3.2)
project (CODE)

find_package( Boost 1.79 COMPONENTS locale unit_test_framework random REQUIRED )
include_directories( ${Boost_INCLUDE_DIRS} )
include_directories( /home/elena/code/crypto3/libs/marshalling/core/include)
include_directories( /home/elena/code/crypto3/libs/algebra/include)
include_directories( /home/elena/code/crypto3/libs/multiprecision/include)
include_directories( /home/elena/code/crypto3/libs/marshalling/algebra/include)
include_directories( /home/elena/code/crypto3/libs/marshalling/multiprecision/include)
include_directories( /home/elena/code/crypto3/libs/hash/include)
include_directories( /home/elena/code/crypto3/libs/block/include)
include_directories( /home/elena/code/crypto3/libs/pubkey/include)
include_directories( /home/elena/code/pixelsig/include)

ADD_EXECUTABLE( code code.cpp )
ADD_EXECUTABLE( bilinearity util/simple_bilinearity.cpp )

link_directories(${Boost_LIBRARY_DIRS})
TARGET_LINK_LIBRARIES( code ${Boost_LIBRARIES})
TARGET_LINK_LIBRARIES( bilinearity ${Boost_LIBRARIES})