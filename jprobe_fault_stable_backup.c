/*
   Source obtained from:
   https://github.com/pradykaushik/Jprobes
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
//SUJAY:#include <asm/rtc.h>
#include <linux/ktime.h>

//SUJAY: Added these lines:
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <asm/tlbflush.h>

#define PTE_RESERVED_MASK	(_AT(pteval_t, 1) << 51)

//structure to hold the information of the proc file
struct proc_dir_entry* my_proc_file;

//kernel buffer to store the result
static char* data_buffer = NULL;

//number of bytes written to data_buffer
static int number_of_bytes = 0;

//fetching the pid from command line arguments.
static int pid=0;
//module_param(pid, int, 0000);

//variable to keep track of number of times proc file was read.
static int temp_len=0;

unsigned long old_address=0;

int my_handler(int pid1){ 
    printk(KERN_ALERT "Syscall intercepted pid1=%d\n",pid1);
    pid = pid1;
    old_address = 0;
    jprobe_return(); 
} 

//function called when read() is called on the proc file
ssize_t my_proc_file_read(struct file* fileptr, char* user_buffer,
		size_t length, loff_t* offset){
/*
	//setting offset to 0 if first time read.
	if(!read_count) {offset = 0;++read_count;}

	if(offset > 0) return 0;//no more data to read from the proc file.
	
	//need to copy the contents of the data buffer to user buffer
	memcpy(user_buffer, data_buffer, number_of_bytes);
	return number_of_bytes;
*/
	/* Send 0 if no more data to send: temp value is decreased
	base on the length of bytes read */
	if(length > temp_len)
		length = temp_len;
	temp_len = temp_len - length;	
	//need to copy the contents of the data buffer to user buffer
	copy_to_user(user_buffer, data_buffer, length);
	return length;	
}

//inserting handler for handle_mm_fault
int my_handle_page_fault1(struct mm_struct* mm, 
	struct vm_area_struct* vma, unsigned long addr,
	unsigned int flags){
	
	//determining current time.
	struct timespec ctime;
	getnstimeofday(&ctime);

	//checking if pid matches.
	if(current->pid == pid){
		/* the addr parameter received seems to be wrong.
		   need to read the faulting address from cr2 */
		unsigned long address;
		address = read_cr2();
		printk(KERN_INFO "virtual_address: 0x%x,\n", address);
		
		//need to concatenate data to the buffer.
		char temp[50] = {0};
		int size = snprintf(temp, 50, "%ld,%x\n", ctime.tv_nsec,address);
		number_of_bytes += (size+1);
		temp_len = number_of_bytes;

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


my_do_page_fault(struct pt_regs *regs, unsigned long error_code,
		unsigned long address)
{
	//checking if pid matches.
	if(current->pid == pid)
	{
		//need to concatenate data to the buffer.
		char temp[50] = {0};
		int size = snprintf(temp, 50, "virtual_address: 0x%x\n", address);
		printk(KERN_INFO "Virt addr:0x%lx\n",address);
		struct vm_area_struct *vma;
		vma = find_vma(current->mm, address);
		if(!vma)
			printk(KERN_INFO "virtual address:0x%x VMA not valid\n", address);
		else if(vma->vm_start <= address && !(error_code & (1<<4)))
		{
		if(error_code & (1 << 3))
		{
			printk("Induced Page Fault, address:0x%lx\n",address);
			pgd_t *pgd;
            p4d_t *p4d;
            pud_t *pud;
            pmd_t *pmd;
            pte_t *pte;

            pgd = pgd_offset(vma->vm_mm, address);
            p4d = p4d_offset(pgd, address);            
            if (!p4d_none(*p4d))
            {
                pud = pud_offset(p4d, address);
                if(!pud_none(*pud))
                {
                    pmd = pmd_offset(pud, address);
                    if(!pmd_none(*pmd))
                    {
                        pte = pte_offset_kernel(pmd, address);
                        if(!pte_none(*pte))
                        {
							*pte = pte_clear_flags(*pte, PTE_RESERVED_MASK);
                        }
                    }
                }
        	}			
		}
		if(old_address!=0 && old_address!=address)
		{
			printk("old addr=%lx\n",old_address);
			pgd_t *pgd;
            p4d_t *p4d;
            pud_t *pud;
            pmd_t *pmd;
            pte_t *pte;

            pgd = pgd_offset(vma->vm_mm, old_address);
            
            p4d = p4d_offset(pgd, old_address);            
            if (!p4d || p4d_none(*p4d))
            	printk(KERN_ERR "Problem with P4D\n");
            else
            {
                pud = pud_offset(p4d, old_address);
                if(!pud || pud_none(*pud))
                    printk(KERN_ERR "Problem with PUD\n");
                else
                {
                    pmd = pmd_offset(pud, old_address);
                    if(!pmd || pmd_none(*pmd))
                        printk(KERN_ERR "Problem with PMD\n");
                    else
                    {
                        pte = pte_offset_kernel(pmd, old_address);
                        if(pte_none(*pte))
                            printk(KERN_ERR "Problem with PTE\n");
                        else
                        {
                            //printk(KERN_INFO "PTE contents = 0x%lx \n",pte_val(*pte));
							
							/* can't do this because the OS will try to swap
							page from swap area */
							*pte = pte_set_flags(*pte, PTE_RESERVED_MASK);
							//printk(KERN_INFO "PTE contents = 0x%lx \n",pte->pte);
							//flush_tlb_page(vma, old_address);
							__flush_tlb_all();
                        }
                    }
                }
        	}
        }  
        old_address = address;     
        }
        
                        
        number_of_bytes += (size+1);
		temp_len = number_of_bytes;

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

/*
//defining the handler and the entry point of the fault handler.
static struct jprobe my_jprobe = {
	.entry = my_handle_page_fault,
	.kp = {
		.symbol_name = "handle_mm_fault",
	},
};
*/
//defining the handler and the entry point of the fault handler.

static struct jprobe my_jprobe = {
	.entry = my_do_page_fault,
	.kp = {
		.symbol_name = "__do_page_fault",
	},
};

static struct jprobe pid_jprobe = {
	.entry = &my_handler, 
	.kp = {
		.symbol_name = "sys_syscall_test",
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

	my_proc_file = proc_create("data_file", 0, NULL, &fops);

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

	//registering module.
	ret = register_jprobe(&pid_jprobe);
	if (ret < 0) {
		printk(KERN_ERR "Error: Register pid_jprobe failed: %d\n", ret);
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
	unregister_jprobe(&pid_jprobe);
	printk(KERN_INFO "jprobe unregistered\n");
}

module_init(jprobe_init);
module_exit(jprobe_exit);
MODULE_LICENSE("GPL");
