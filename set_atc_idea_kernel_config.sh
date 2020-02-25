#!/bin/bash

cp atc_idea_config arch/x86/configs/my_defconfig

export ARCH=x86
make my_defconfig


