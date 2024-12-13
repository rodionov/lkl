#!/bin/bash

PROTO_NAME=binder

SCRIPT=$(readlink -f "$0")
DIRNAME=$(dirname "$SCRIPT")
PROTOC=protoc

rm -f $DIRNAME/$PROTO_NAME.pb.cc $DIRNAME/$PROTO_NAME.pb.h
$PROTOC --cpp_out=$DIRNAME --proto_path=$DIRNAME $PROTO_NAME.proto

# tools/build/Makefile.build expects %.cpp
mv $DIRNAME/$PROTO_NAME.pb.cc $DIRNAME/$PROTO_NAME.pb.cpp