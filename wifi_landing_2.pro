TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += main.cpp \
    mac.cpp \
    http_injection.cpp

HEADERS += \
    mac.h \
    key_value.h \
    http_injection.h
