TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += main.cpp \
    mac.cpp

HEADERS += \
    mac.h \
    mac.h \
    key_value.h
