#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/rtc.h>
#include <linux/ktime.h>

//structure to hold the information of the proc file
struct proc_dir_entry* my_proc_file;

//kernel buffer to store the result
static char* data_buffer = NULL;

//number of bytes written to data_buffer
static int number_of_bytes = 0;

//fetching the pid from command line arguments.
static int pid;
module_param(pid, int, 0000);

//variable to keep track of number of times proc file was read.
static int read_count = 0;

//function called when read() is called on the proc file
ssize_t my_proc_file_read(struct file* fileptr, char* user_buffer,
		size_t length, loff_t* offset){

	//setting offset to 0 if first time read.
	if(!read_count) {offset = 0;++read_count;}

	if(offset > 0) return 0;//no more data to read from the proc file.
	
	//need to copy the contents of the data buffer to user buffer
	memcpy(user_buffer, data_buffer, number_of_bytes);
	return number_of_bytes;
}

//inserting handler for handle_mm_fault
int my_handle_page_fault(struct mm_struct* mm, 
	struct vm_area_struct* vma, unsigned long addr,
	unsigned int flags){
	
	//determining current time.
	struct timespec ctime;
	getnstimeofday(&ctime);

	//checking if pid matches.
	if(current->pid == pid){
		printk(KERN_INFO "pid: %d, virtual_address: %lu\n", current->pid, addr);
		
		//need to concatenate data to the buffer.
		char temp[50] = {0};
		int size = snprintf(temp, 50, "%ld,%lu\n", ctime.tv_nsec,addr);
		number_of_bytes += (size+1);

		//maybe we need to allocate memory.
		if(data_buffer == NULL){
			data_buffer = (char*)kzalloc(sizeof(char)*
				number_of_bytes, GFP_KERNEL);
		}
		else{
			data_buffer = (char*)krealloc(data_buffer, 
				number_of_bytes, GFP_KERNEL);
		}
		strcat(data_buffer, temp);
	}
	jprobe_return();
	return 0;
}

//defining the handler and the entry point of the fault handler.
static struct jprobe my_jprobe = {
	.entry = my_handle_page_fault,
	.kp = {
		.symbol_name = "handle_mm_fault",
	},
};

//setting the function called when proc file is read.
static struct file_operations fops = {
	.read = &my_proc_file_read,
	.owner = THIS_MODULE,
};

//init module.
static int __init jprobe_init(void)
{
	int ret;
	//creating proc file.
	my_proc_file = proc_create("data_file", 0755, NULL, &fops);

	//checking if proc file was created.
	if(my_proc_file == NULL){
		remove_proc_entry("data_file", NULL);
		printk(KERN_ERR "Error: Could not initialize /proc/%s file\n", "data_file");
		return -1;
	}

	//registering module.
	ret = register_jprobe(&my_jprobe);
	if (ret < 0) {
		printk(KERN_ERR "Error: Register_jprobe failed: %d\n", ret);
		return -1;
	}

	printk(KERN_INFO "Success: Planted jprobe at %p\n",my_jprobe.kp.addr);
	return 0;
}

//exit module.
static void __exit jprobe_exit(void)
{
	kfree(data_buffer);
	remove_proc_entry("data_file", NULL);
	unregister_jprobe(&my_jprobe);
	printk(KERN_INFO "jprobe unregistered\n");
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");
