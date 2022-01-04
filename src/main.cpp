#ifndef WIN32
#define WIN32
#endif
#include <Winsock2.h>
#include <infiniband/verbs.h>

extern CRITICAL_SECTION lock;
extern HANDLE heap;

int main(int argc, char** argv)
{
	heap = HeapCreate(0, 0, 0);
	if (heap == NULL) {
		return FALSE;
	}
	InitializeCriticalSection(&lock);

	int num_devices;
	auto** devs = ibv_get_device_list(&num_devices);

	for (int i = 0; i < num_devices; i++)
	{
		uint64_t lid = 0;
		ibv_device* dev;
		auto ctx = ibv_open_device(devs[i]);
		int Nports = 0;
		if (ctx)
		{
			// Loop over port numbers
			for (uint8_t port_num = 1; port_num < 10; port_num++) { // (won't be more than 2!)
				struct ibv_port_attr my_port_attr;
				auto ret = ibv_query_port(ctx, port_num, &my_port_attr);
				if (ret != 0) break;
				Nports++;
				if (my_port_attr.lid != 0) {
					lid = my_port_attr.lid;
					dev = devs[i];
					//this->port_num = port_num;
				}
			}
			ibv_close_device(ctx);
		}
	}

	DeleteCriticalSection(&lock);
	HeapDestroy(heap);
	return 0;
}