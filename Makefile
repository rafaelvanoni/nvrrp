#
# This file is part of the nvrrp project (https://launchpad.net/nvrrp/)
#
# Copyright (C) 2016   Pluribus Networks
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

TARGET	= nvrrp
CWARN	= -Wall -Werror -Wformat -Wformat-security -Wunused -Wpedantic
CFLAGS	= -g -std=c18 -m64 -D_FORTIFY_SOURCE=2 -fstack-protector -D_GNU_SOURCE
DEPS	= -MD -MF $(TARGET).d
LIBS	= -lbsd -lpthread -lrt
OPT	= -O3

all: $(TARGET)

clean:
	$(RM) $(TARGET).d $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CWARN) $(OPT) $(DEPS) $(CFLAGS) $(TARGET).c -o $(TARGET) $(LIBS)

-include $(TARGET).d
