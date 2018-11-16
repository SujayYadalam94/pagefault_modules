/*
   Initial source obtained from:
   https://github.com/pradykaushik/Jprobes
   Thanks to him.
   
   Note to self: Disable ASLR before testing. Runs only with Linux verions 4.14.0 and before
   because JProbes was disabled afterwards. Linux Kernel needs to be modified as documented
   in my OneNote page.
   
   echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

/*
	SUJAY: Added these lines:
*/
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/huge_mm.h>
#include <linux/hugetlb.h>
#include <asm/tlbflush.h>

#define PTE_RESERVED_MASK	(_AT(pteval_t, 1) << 51)
#define PF_PROT	 (1<<0)
#define PF_RSVD	 (1<<3)
#define PF_INSTR (1<<4)

/* 
	Function declarations
*/
static void my_do_page_fault(struct pt_regs *regs, unsigned long error_code, unsigned long address);
int syscall_handler(int _pid);
ssize_t pgfault_file_read(struct file* fileptr, char* user_buffer, size_t length, loff_t* offset);

/*
	Function pointers: Required because some kernel
	symbols are not accessible although they are present
	in the /proc/kallsyms file
*/
static struct task_struct* (*find_task_by_vpid_p)(int);
static struct mm_struct* (*get_task_mm_p)(struct task_struct *task);
static void (*mmput_p)(struct mm_struct *);
static void (*flush_tlb_mm_range_p)(struct mm_struct *mm, unsigned long start,
				unsigned long end, unsigned long vmflag);


//structure to hold the page faults in a proc file
struct proc_dir_entry* pgfault_file;

//kernel buffer to store the result
static char* data_buffer = NULL;

//number of bytes written to data_buffer
static int number_of_bytes = 0;
static int temp_len=0;

/*
	PID of the process of interest is obtained
	by intercepting the syscall
*/
static int pid = -1;

static int log=0;

/*
	variables to keep track of old fault addresses.
	History of 4 addresses is required to detect
	repitive pattern and both the alternating pages
*/
unsigned long prev_address=0, old_prev=0, new_prev=0, mk_reserve_address=0;



//defining the handler and the entry point of the fault handler.
static struct jprobe pgfault_jprobe = {
	.entry = my_do_page_fault,
	.kp = {
		.symbol_name = "__do_page_fault",
	},
};

//Intercepting the syscall to capture the pid and modify the PTEs 
static struct jprobe syscall_jprobe = {
	.entry = &syscall_handler, 
	.kp = {
		.symbol_name = "sys_syscall_test",
	},
};

//setting the function called when proc file is read.
static struct file_operations fops = {
	.read = &pgfault_file_read,
	.owner = THIS_MODULE,
};

/*
	This function is called when the syscall is made.
	This function is used to either make all the valid PTEs
	reserved or unreserved(when exiting).
*/
int make_page_entries_reserved(bool reserved)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	
	unsigned long i,k,l,m;
	unsigned int num_entries_modified = 0;
	unsigned int pmd_entries_modified = 0;
	pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
	unsigned long address;
	
	/*
		We want to ensure that we make only PTEs corresponding
		to user pages and those pages that are present reserved.
	*/
	unsigned long mask = _PAGE_USER | _PAGE_PRESENT;
	
	tsk = find_task_by_vpid_p(pid);
	
	/*
	 	Need to make sure that mm is valid before trying to access.
	 	Previously it was tsk->mm; if the process gets killed, tsk is NULL
	 	and tsk->mm will return in an error.
	 */	
	mm = get_task_mm_p(tsk);
	if(!mm)
		return 0;
	/* 
	 	Had to remove P4D because it is not used in 4 level tables,
	 	which is the case with current Linux kernel. Using it caused problems.
	 */
	for(i=0;i<PTRS_PER_PGD;i++)
	{
		pgd = mm->pgd + i;
		if((pgd_flags(*pgd) & mask) != mask)
			continue;
		for(k=0;k<PTRS_PER_PUD;k++)
		{
			pud = (pud_t *)pgd_page_vaddr(*pgd) + k;
			if((pud_flags(*pud) & mask) != mask)
				continue;
			for(l=0;l<PTRS_PER_PMD;l++)
			{
				pmd = (pmd_t *)pud_page_vaddr(*pud) + l;
				if((pmd_flags(*pmd) & mask) != mask)
					continue;
				address = (i<<PGDIR_SHIFT) + (k<<PUD_SHIFT) + (l<<PMD_SHIFT);
				vma = find_vma(mm, address);
				if(vma && pmd_trans_huge(*pmd) && (vma->vm_flags & VM_EXEC))
				/*
					If Transparent huge pages are not enabled to "always", then
					the below flag might not be set. I should be using || instead
					of &&.
				*/
				//&& (transparent_hugepage_enabled(vma)) 
				{
					spin_lock(&mm->page_table_lock);
					if(reserved)
						*pmd = pmd_set_flags(*pmd, PTE_RESERVED_MASK);
					else
						*pmd = pmd_clear_flags(*pmd, PTE_RESERVED_MASK);
					spin_unlock(&mm->page_table_lock);
					flush_tlb_mm_range_p(mm, address, address+PAGE_SIZE, VM_NONE);
					pmd_entries_modified++;
					/*
						Temporary workaround to log if largepages
						are used. Since the pattern never matches, addresses
						will not be logged.
					*/
					log=1;
					continue;
				}
				for(m=0;m<PTRS_PER_PTE;m++)
				{
					pte = (pte_t *)pmd_page_vaddr(*pmd) + m;
					if((pte_flags(*pte) & mask) != mask)
						continue;
					address = (i<<PGDIR_SHIFT) + (k<<PUD_SHIFT) + (l<<PMD_SHIFT) + (m<<PAGE_SHIFT);
					vma = find_vma(mm, address);
					if(vma && (vma->vm_start <= address) && (vma->vm_end >= address))
					{
						if(vma->vm_flags & VM_EXEC)
						{
							spin_lock(&mm->page_table_lock);
							if(reserved)
								*pte = pte_set_flags(*pte, PTE_RESERVED_MASK);
							else
								*pte = pte_clear_flags(*pte, PTE_RESERVED_MASK);
							spin_unlock(&mm->page_table_lock);
							flush_tlb_mm_range_p(mm, address, address+PAGE_SIZE, VM_NONE);
							num_entries_modified++;
						}
					}
				}
			}
		}
	}
	//__flush_tlb_all();
	mmput_p(mm);
	
	printk(KERN_INFO "Modified %d PMD entries\n", pmd_entries_modified);
	
	return num_entries_modified;
}

/*
	Function to mark the PTE of a particular address as reserved.
*/
void mk_entry_reserved(struct vm_area_struct *vma, unsigned long address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(vma->vm_mm, address);

	p4d = p4d_offset(pgd, address);            
	if (!p4d || p4d_none(*p4d))
		return;
	else
	{
		pud = pud_offset(p4d, address);
		if(!pud || pud_none(*pud))
			return;
		else
		{
			pmd = pmd_offset(pud, address);
			if(!pmd || pmd_none(*pmd))
				return;
			else if(pmd_trans_huge(*pmd))
			// && (transparent_hugepage_enabled(vma)))
			{
				spin_lock(&vma->vm_mm->page_table_lock);
				*pmd = pmd_set_flags(*pmd, PTE_RESERVED_MASK);
				spin_unlock(&vma->vm_mm->page_table_lock);	 				
				flush_tlb_mm_range_p(vma->vm_mm, address, address+PAGE_SIZE, VM_NONE);	
				printk(KERN_INFO "PMD entry resrved\n");
			}
			else
			{
				pte = pte_offset_kernel(pmd, address);
				if(pte_none(*pte))
					return;
				else
				{
					spin_lock(&vma->vm_mm->page_table_lock);
					*pte = pte_set_flags(*pte, PTE_RESERVED_MASK);
					spin_unlock(&vma->vm_mm->page_table_lock);	
					/*	Symbol for flushing only a page is not
						accessible.	*/		  				
					flush_tlb_mm_range_p(vma->vm_mm, address, address+PAGE_SIZE, VM_NONE);
				}
			}
		}
	}
}

/*
	Syscall 333 (implemented by us) is intercepted by this handler
*/
int syscall_handler(int _pid)
{ 
    int ret = 0;
        
    prev_address = 0;
    old_prev = 0;
    new_prev = 0;
    number_of_bytes=0;
    log=0;
    
    printk(KERN_ALERT "Syscall intercepted pid=%d\n",_pid);
    
    /*  PID of -1 is used when you want to stop tracking the
    	page faults for the process  */
    if(_pid == -1)
   	{
   		current->mm->cca_en = 0;
   		ret = make_page_entries_reserved(false);
	   	if(ret == 0)
   			printk(KERN_ALERT "No page table entry cleared.\n");   		
		else
   			printk(KERN_INFO "Cleared %d entries\n", ret);
		pid = _pid;
		
   		jprobe_return();
   	}
   	
    pid = _pid;
 
	current->mm->cca_en = 1;
   	ret = make_page_entries_reserved(true);
   	if(ret == 0)
   		printk(KERN_ALERT "No page table entry modified.\n");
   	else
   		printk(KERN_INFO "Modified %d entries\n", ret);
    jprobe_return(); 
} 

/*
	Function called when proc file is read
*/
ssize_t pgfault_file_read(struct file* fileptr, char* user_buffer, size_t length, loff_t* offset)
{
	/* Send 0 if no more data to send: temp value is decreased
	base on the length of bytes read */
	if(length > number_of_bytes)
		length = number_of_bytes;
	number_of_bytes = number_of_bytes - length;	
	
	//need to copy the contents of the data buffer to user buffer
	copy_to_user(user_buffer, data_buffer, length);
	return length;	
}

/* 
	my_do_page_fault is called on a page fault before __do_page_fault
	is invoked.
*/
static void my_do_page_fault(struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
	struct vm_area_struct *vma;

	//checking if pid matches.
	if(current->pid == pid)
	{	
		/* 
			We are purposefully masking the lower 12 bits because that's
			what the enclave passes to the OS in Intel SGX.
		*/
		address &= ~0xFFF;	
		
		/*
			IMPORTANT: We are interested in tracking page faults inside a function
			called "load_truetype_glyph" inside TT_Load_Glyph. The below sequence
			of faults are used to detect the start of the function. We log the faults
			only after this function is invoked.
		*/
		//if(new_prev==0x7ffff7b53000 && prev_address==0x7ffff7b6c000 && address == 0x7ffff7b6d000)
		if(new_prev==0x433000 && prev_address==0x434000 && address == 0x431000)
			log=1;
			
		vma = find_vma(current->mm, address);
		if(!vma)
			printk(KERN_INFO "virtual address:0x%x VMA not valid\n", address);
		else if(vma->vm_start <= address)
		{
			if((error_code & PF_INSTR) && log)
			{
				printk(KERN_INFO "0x%lx\n", address);

				/*
					CAUTION: Do not uncomment this. Uncommenting can cause
					segmentation fault. This is mostly because the mallocs
					we are using. We might have to either free the memory
					or look closer at the issue.
				*/
				/*
				//need to concatenate data to the buffer.
				char temp[50] = {0};
		
				int size = snprintf(temp, 20, "0x%lx\n", address);
				number_of_bytes += (size+1);
				temp_len = number_of_bytes;
	
				//maybe we need to allocate memory.
				if(data_buffer == NULL)
					data_buffer = (char*)kzalloc(sizeof(char)*number_of_bytes, GFP_KERNEL);
				else
					data_buffer = (char*)krealloc(data_buffer, number_of_bytes, GFP_KERNEL);
				strcat(data_buffer, temp);		
				*/
			}		
			
			/* 
				If the fault occurred with the PF_RSVD bit set, we need to 
			 	handle the fault as the default handler is not cannot handle.
			 */
			if(error_code & PF_RSVD)
			{
				//if(error_code & PF_INSTR)
				//	printk("Induced Page Fault\n");
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
    	                if(pmd_trans_huge(*pmd))
    	                // && (transparent_hugepage_enabled(vma)))
    	                {
    	                	spin_lock(&vma->vm_mm->page_table_lock);
    	                	*pmd = pmd_clear_flags(*pmd, PTE_RESERVED_MASK);
    	                	spin_unlock(&vma->vm_mm->page_table_lock);
    	                	printk(KERN_INFO "PMD entry cleared\n");
    	                }
	                    else if(!pmd_none(*pmd))
	                    {
	                        pte = pte_offset_kernel(pmd, address);
	                        if(!pte_none(*pte))
	                        {
	                        	spin_lock(&vma->vm_mm->page_table_lock);
								*pte = pte_clear_flags(*pte, PTE_RESERVED_MASK);
								spin_unlock(&vma->vm_mm->page_table_lock);
	                        }
	                    }
	                }
	        	}			
			}
			
			/*
				When a repitative pattern is observed, we make both the pages
				accessible. Therefore on the next fault (on a different page),
				we need to make both the pages reserved.
			*/
			if(mk_reserve_address)
			{
				mk_entry_reserved(vma, mk_reserve_address);
	        	mk_reserve_address = 0; 
	        }	
	        
			/* 
				Important: below checks make sure that we don't get stuck at a particular 
			 	address. 
			*/			
			if((old_prev == prev_address) && (new_prev == address))
			{
				mk_reserve_address = prev_address;
			}
			else if(prev_address!=0)
			{
				mk_entry_reserved(vma, prev_address);
	        }       
	        
	        old_prev = new_prev;
	        new_prev = prev_address;
	        /* mark only code pages */
	        if(vma->vm_flags & VM_EXEC)
		        prev_address = address;
		    else
		    	prev_address = 0;
	    }
	}
	jprobe_return();
}
	
//init module.
static int __init jprobe_init(void)
{
	int ret;
	
	//creating proc file.
	pgfault_file = proc_create("pgfault_file", 0, NULL, &fops);

	//checking if proc file was created.
	if(pgfault_file == NULL){
		remove_proc_entry("pgfault_file", NULL);
		printk(KERN_ERR "Error: Could not initialize /proc/%s file\n", "pgfault_file");
		return -1;
	}

	//registering module.
	ret = register_jprobe(&pgfault_jprobe);
	if (ret < 0) {
		printk(KERN_ERR "Error: Register_jprobe failed: %d\n", ret);
		return -1;
	}

	//registering module.
	ret = register_jprobe(&syscall_jprobe);
	if (ret < 0) {
		printk(KERN_ERR "Error: Register pid_jprobe failed: %d\n", ret);
		return -1;
	}
	
	/* 
	 	Below symbols seem to be not exported from the Linux kernel.
	 	So not able to use it directly. A workaround is to lookup the name
	 	and use a function pointer.
	*/
	flush_tlb_mm_range_p = (void *) kallsyms_lookup_name("flush_tlb_mm_range");
	find_task_by_vpid_p = (void *) kallsyms_lookup_name("find_task_by_vpid");
	get_task_mm_p = kallsyms_lookup_name("get_task_mm");
	mmput_p = (void *)kallsyms_lookup_name("mmput");

	printk(KERN_INFO "Success: Module Initiated\n");
	return 0;
}

//exit module.
static void __exit jprobe_exit(void)
{
	kfree(data_buffer);
	remove_proc_entry("pgfault_file", NULL);
	unregister_jprobe(&pgfault_jprobe);
	unregister_jprobe(&syscall_jprobe);
	printk(KERN_INFO "Module exited\n");
}

module_init(jprobe_init);
module_exit(jprobe_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sujay");
MODULE_DESCRIPTION("Tracks page faults of a process");
