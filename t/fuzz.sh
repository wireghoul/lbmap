#!/bin/sh
for file in `ls cases/*`; do
echo -n "$file "
./request.sh $file $1 $2
done

