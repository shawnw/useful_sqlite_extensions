#!/bin/sh

# Examples of csv2sqlite usage

db=demo.db
rm -f "$db"

# Basic import
./csv2sqlite --verbose "$db" test1 <<EOF
id,animal
1,dog
2,cat
3,fish
4,turtle
EOF

# Import into a new table with an integer primary key
./csv2sqlite --verbose --ipk=id "$db" test2 <<EOF
id,animal
1,dog
2,cat
3,fish
4,turtle
EOF

# Import into a new table with default affinities, storing numeric
# values as numbers instead of strings. Also demonstrate default
# handling of leading spaces in fields, and quoted fields.
./csv2sqlite --verbose --guess-types "$db" test3 <<EOF
id,example
1,a string
2,"a quoted string"
3,"a quoted string with ""quotes"""
4, a string with a leading space
5," a quoted leading space"
EOF

# Same but stripping leading spaces in fields of badly formed CSV
./csv2sqlite --verbose --guess-types --headers --strip "$db" test3 <<EOF
id,example
6, a string with a leading space
7," a quoted leading space"
8, "a quoted string with unquoted leading space"
9, " a quoted string with unquoted leading space and quoted leading space"
EOF

# Creating a new table with user-defined column names instead of
# using the first line.
./csv2sqlite --verbose --columns=fname,lname "$db" test4 <<EOF
John,Smith
Jane,Doe
EOF

# Same but using the first line to determine the order of fields in the input.
./csv2sqlite --verbose --columns=fname,lname --headers "$db" test5 <<EOF
lname,fname
Lincoln,Abraham
Polk,James
EOF

