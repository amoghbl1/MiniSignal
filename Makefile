protobuf: clean server-keys
	protoc -I=. --python_out=. messages.proto

clean:
	rm -rf *.pyc
	rm -rf *_pb2.py
	rm -rf server.*

server-keys:
	./key_generator.py -g server
