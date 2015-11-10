test:
	gcc -o snooping_client snooping_client.c ../cache_rule/libcacherule.a -lcurl -Wall

android:
	arm-linux-androideabi-gcc -o snooping_client snooping_client.c -I/home/zy/libcurl/include /home/zy/libcurl/lib/libcurl.a -lz ../cache_rule/libcacherule.a -Wall

clean:
	rm -rf snooping_client
