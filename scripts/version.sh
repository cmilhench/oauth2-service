#!/bin/sh

git describe --tags --long --dirty --always | tr -d '\n'
