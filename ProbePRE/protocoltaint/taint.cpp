#include <asm/unistd.h>
#include <vector>
#include <set>
#include "config.hpp"
#include "logic.hpp"
#include "pin.H"
#include "pinobject.hpp"
#include "util.hpp"
#include "loop.cpp"


bool filter_ins(Ins ins) {
    // filter rules
    UINT32 opcount = ins.OpCount();

    bool ret = ins.isCall() || ins.isRet() || ins.isBranch() || ins.isNop() || opcount <= 1 || opcount >= 5
        || ins.Extention() > 40 ;
    /* static cache - record filtered ins's opcode to delete duplicate info*/
    static std::vector<OPCODE> cache;
    if (ret) {
        OPCODE opcode = ins.OpCode();
        if (std::find(cache.begin(), cache.end(), opcode) == cache.end()) {
            cache.push_back(opcode);
        }
    }

    return ret;
}

void LogInst(Ins ins) {
    if (!config::debugMode) return;//default on
    /* if need filter curr ins*/
    if (filter_ins(ins) ) {
        INS_InsertPredicatedCall(
        ins, IPOINT_BEFORE, (AFUNPTR)print_instructions0,
        IARG_PTR, new std::string(ins.Name()), IARG_INST_PTR,
        IARG_END);
        return;
    }
    /* Determine whether memory operations is involved */
    if (ins.isOpMem(0)) {
        /* two mem operands */
        if (ins.isOpMem(1)) {
            /* Insert callback func - record detail info (ins name, ins addr, ctxt, two OpReg r1&r2, two MemAddr m1&m2)*/
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)print_instructions1,
                IARG_PTR, new std::string(ins.Name()), IARG_INST_PTR,
                IARG_CONST_CONTEXT,

                IARG_ADDRINT, ins.OpReg(0),
                IARG_ADDRINT, ins.OpReg(1),
                
                IARG_MEMORYOP_EA, 0,

                IARG_MEMORYOP_EA, 1,

                IARG_END);
        } else {/* one mem operands */
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)print_instructions1,
                IARG_PTR, new std::string(ins.Name()), IARG_INST_PTR,
                IARG_CONST_CONTEXT,

                IARG_ADDRINT, ins.OpReg(0),
                IARG_ADDRINT, ins.OpReg(1),

                IARG_MEMORYOP_EA, 0,

                IARG_ADDRINT, 0,//turn args into Integer

                IARG_END);
        }
    } else {
        /* zero mem operands */
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)print_instructions1,
            IARG_PTR, new std::string(ins.Name()), IARG_INST_PTR,
            IARG_CONST_CONTEXT,

            IARG_ADDRINT, ins.OpReg(0),
            IARG_ADDRINT, ins.OpReg(1),
            IARG_ADDRINT, 0,

            IARG_ADDRINT, 0,

            IARG_END);
    }
}

bool isCmp(INS ins) {
    const std::string *insName = new std::string(INS_Disassemble(ins));
    if (strstr(insName->c_str(), "cmp") != NULL) {
        return true;
    }
    return false;
}

bool isJump(INS ins) {
    if (INS_IsBranch(ins) && !INS_IsCall(ins) && !INS_IsRet(ins)) {
        return true;
    }
    return false;
}

void Instruction(Ins ins) {
    
    UINT32 opcount = ins.OpCount();

    if ( filter_ins(ins) ) {
        return;
    }
    /* tag if ins match a known operation types*/
    bool miss = false;

    OPCODE opcode = ins.OpCode();
    
    REG reg_w = ins.OpReg(0);
    REG reg_r = ins.OpReg(1);

    //识别setnz 打补丁
    std::string mnemonic = INS_Mnemonic(ins);

    if (mnemonic == "setnz" || mnemonic == "SETNZ") {
        process_setnz(ins);
    }

    if (opcount == 2) {/* write & read operations*/
        if (ins.isLea()) {// reg calculation
            REG baseReg;
            REG indexReg;
            UINT32 displacement;
            UINT32 scale;
            baseReg = INS_MemoryBaseReg(ins);
            indexReg = INS_MemoryIndexReg(ins);
            displacement = INS_OperandMemoryDisplacement(ins, 1);
            scale = INS_OperandMemoryScale(ins, 1);
            InsertCallForLea(ins, reg_w, baseReg, indexReg, displacement, scale); //lea指令也会发挥add或sub指令的作用
        } else if (ins.isOpReg(0) && ins.isOpMem(1)) {//reg <- mem
            REG mem_indexReg;
            mem_indexReg = INS_MemoryIndexReg(ins);
            InsertCall(ins, reg_w, 0, mem_indexReg);                  // ReadMem
        } else if (ins.isOpMem(0) && ins.isOpReg(1)) {//mem <- reg
            InsertCall(ins, 0, reg_r);                  // WriteMem
        } else if (ins.isOpMem(0) && ins.isOpImm(1)) {//mem <- imm
            InsertCall(ins, 0);                         // deleteMem
        } else if (ins.isOpReg(0) && ins.isOpReg(1)) {//reg <- reg
            InsertCall(ins, reg_w, reg_r);              // spreadReg
        } else if (ins.isOpReg(0) && ins.isOpImm(1)) {//reg <- imm
            InsertCall(ins, reg_w);                     // deleteReg
        } else {
            miss = true;//Mismatch with any known type
        }
    } else if (opcount == 3) {/* logical & arithmetic operations */
        if(isCmp(ins) && isJump(INS_Next(ins))){
            if (ins.isOpReg(0) && ins.isOpReg(1)) {       //reg & reg
                ConstraintExtra(ins, reg_w, reg_r); //
            } else if (ins.isOpReg(0) && ins.isOpMem(1)) {//reg & mem
                ConstraintExtra(ins, reg_w, 0); 
            } else if (ins.isOpReg(0) && ins.isOpImm(1)) {//reg & imm
                ConstraintExtra(ins, reg_w); 
            } else if (ins.isOpMem(0) && ins.isOpImm(1)) {//mem & imm
                ConstraintExtra(ins, 0); 
            } else if (ins.isOpMem(0) && ins.isOpReg(1)) {//mem & reg 
                ConstraintExtra(ins, 0, reg_r);
            }
        }else if (ins.isOpReg(0) && ins.isOpReg(1)) {       //reg & reg
            InsertCallExtra(ins, reg_w, reg_r); //
        } else if (ins.isOpReg(0) && ins.isOpMem(1)) {//reg & mem
            InsertCallExtra(ins, reg_w, 0); 
        } else if (ins.isOpReg(0) && ins.isOpImm(1)) {//reg & imm
            InsertCallExtra(ins, reg_w); 
        } else if (ins.isOpMem(0) && ins.isOpImm(1)) {//mem & imm
            InsertCallExtra(ins, 0); 
        } else if (ins.isOpMem(0) && ins.isOpReg(1)) {//mem & reg 
            InsertCallExtra(ins, 0, reg_r);
        } else {
            miss = true;
        }
    } else if (opcount == 4) {/* PUSH & POP operations*/
        if (opcode == XED_ICLASS_PUSH) {  // push
            if (ins.isOpReg(0)) {//mem <- reg 
                InsertCall(ins, 0, reg_w);  // WriteMem 
            } else if (ins.isOpMem(0)) {//mem <- mem
                InsertCall(ins, 0, 1);  // spreadMem
            } else if (ins.isOpImm(0)) {//mem <- imm
                InsertCall(ins, 0);  // deleteMem
            } else {
                miss = true;
            }
        } else if (opcode == XED_ICLASS_POP) {  // pop
            if (ins.isOpReg(0)) {
                InsertCall_pop(ins, reg_w, 0);  // ReadMempop
            } else {
                miss = true;
            }
        } else {
            miss = true;
        }
    }
    /* Record ins, which is unable to analyze*/
    if (config::missFlag && miss) {
        static std::vector<OPCODE> cache;
        if (std::find(cache.begin(), cache.end(), opcode) == cache.end()) {
            cache.push_back(opcode);
            logger::debug("assembly not taint included : %s %d %d\n",
                          ins.Name().c_str(), reg_w, reg_r);
        }
    }

}


void Image(IMG img, VOID *v) {
    std::string imgName = IMG_Name(img);
    const bool isMain = IMG_IsMainExecutable(img);
    const bool isWrapper = (imgName.find("libx.so") != std::string::npos);
    const bool isLib = filter::libs(imgName);

    if (!(isMain || isWrapper || isLib)) return;
    
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        
        for (Rtn rtn = SEC_RtnHead(sec); rtn.Valid(); rtn = rtn.Next()) {
            if (rtn.isArtificial()){
                continue;
            } 
            /* function name*/
            std::string *rtnName = new std::string(rtn.Name());
            
            if (filter::blackfunc(*rtnName)) continue;
            rtn.Open();
            /* Insert callback functions to : print instrumented functions name and their args*/
            if (config::debugMode) {
                RTN_InsertCall(
                    rtn, IPOINT_BEFORE, (AFUNPTR)print_functions,
                    IARG_PTR, rtnName,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                    IARG_END);
            }
            /* Do deeper instrumentation for 'Main' and 'Lib' functions*/
            if (isMain || isLib) {
                /* Insert callback into func's Entry (record thread id, function name, address of the first and last instruction, return addr)*/
                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)function_entry,
                                IARG_THREAD_ID, IARG_PTR, rtnName, 
                                IARG_ADDRINT, rtn.InsHead().Address(),
                                IARG_ADDRINT, rtn.InsTail().Address(),
                                IARG_RETURN_IP,
                                IARG_END);
                /* Insert callback into func's Entry*/
                RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)function_exit,
                                IARG_THREAD_ID, IARG_PTR, rtnName, 
                                IARG_END);
                for (Ins ins = rtn.InsHead(); ins.Valid(); ins = ins.Next()) {
                    /* Record ins address and assemnbly code*/
                    // LogInst(ins);
                    /* Handle Ins*/
                    // logger::info("PREInstruction %s\n", ins.Name().c_str());
                    Instruction(ins);
                }
            } 
            if (isWrapper) {
            /* According function names, insert different callback funcs */
                if (*rtnName == "read") {//Reading data from a file or file descriptor
                    RTN_InsertCall(
                        rtn, IPOINT_BEFORE, (AFUNPTR)read_point,
                        IARG_ADDRINT, filter::entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // fd
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                    RTN_InsertCall(
                        rtn, IPOINT_AFTER, (AFUNPTR)read_point,
                        IARG_ADDRINT, filter::exit,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // fd
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                } else if (*rtnName == "recv") {//Read data from a network socket
                    RTN_InsertCall(
                        rtn, IPOINT_BEFORE, (AFUNPTR)recv_point,
                        IARG_ADDRINT, filter::entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                    RTN_InsertCall(
                        rtn, IPOINT_AFTER, (AFUNPTR)recv_point,
                        IARG_ADDRINT, filter::exit,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                } else if (*rtnName == "recvfrom") {// Read data from network socket and return sender address
                    RTN_InsertCall(
                        rtn, IPOINT_BEFORE, (AFUNPTR)recvfrom_point,
                        IARG_ADDRINT, filter::entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 4,  // address
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 5,  // address_len
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                    RTN_InsertCall(
                        rtn, IPOINT_AFTER, (AFUNPTR)recvfrom_point,
                        IARG_ADDRINT, filter::exit,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 4,  // address
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 5,  // address_len
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                } else if (*rtnName == "recvmsg") {//Read data from a network socket and return more information
                    RTN_InsertCall(
                        rtn, IPOINT_BEFORE, (AFUNPTR)recvmsg_point,
                        IARG_ADDRINT, filter::entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // msghdr
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // flags
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                    RTN_InsertCall(
                        rtn, IPOINT_AFTER, (AFUNPTR)recvmsg_point,
                        IARG_ADDRINT, filter::exit,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // msghdr
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // flags
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                } 
                // else if (*rtnName == "write") {//Write data to a file or file descriptor
                //     RTN_InsertCall(
                //         rtn, IPOINT_BEFORE, (AFUNPTR)write_point,//Not taint
                //         IARG_ADDRINT, filter::entry,
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // fd
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                //         IARG_REG_VALUE, REG_RAX,           // ret
                //         IARG_END);
                //     RTN_InsertCall(
                //         rtn, IPOINT_AFTER, (AFUNPTR)write_point,//fix bug
                //         IARG_ADDRINT, filter::exit,
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // fd
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                //         IARG_REG_VALUE, REG_RAX,           // ret
                //         IARG_END);
                // } else if (*rtnName == "send") {//Writes data to the socket
                //     RTN_InsertCall(
                //         rtn, IPOINT_BEFORE, (AFUNPTR)send_point,
                //         IARG_ADDRINT, filter::entry,
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                //         IARG_REG_VALUE, REG_RAX,           // ret
                //         IARG_END);
                //     RTN_InsertCall(
                //         rtn, IPOINT_AFTER, (AFUNPTR)send_point,
                //         IARG_ADDRINT, filter::exit,
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                //         IARG_REG_VALUE, REG_RAX,           // ret
                //         IARG_END);
                // } else if (*rtnName == "sendto") {//Writes data to the socket and specifies address information for the receiver.
                //     RTN_InsertCall(
                //         rtn, IPOINT_BEFORE, (AFUNPTR)sendto_point,
                //         IARG_ADDRINT, filter::entry,
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 4,  // address
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 5,  // address_len
                //         IARG_REG_VALUE, REG_RAX,           // ret
                //         IARG_END);
                //     RTN_InsertCall(
                //         rtn, IPOINT_AFTER, (AFUNPTR)sendto_point,
                //         IARG_ADDRINT, filter::exit,
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 4,  // address
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 5,  // address_len
                //         IARG_REG_VALUE, REG_RAX,           // ret
                //         IARG_END);
                // } else if (*rtnName == "sendmsg") {//Writes data to the socket and returns more information
                //     RTN_InsertCall(
                //         rtn, IPOINT_BEFORE, (AFUNPTR)sendmsg_point,
                //         IARG_ADDRINT, filter::entry,
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // msghdr
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // flags
                //         IARG_REG_VALUE, REG_RAX,           // ret
                //         IARG_END);
                //     RTN_InsertCall(
                //         rtn, IPOINT_AFTER, (AFUNPTR)sendmsg_point,
                //         IARG_ADDRINT, filter::exit,
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // msghdr
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // flags
                //         IARG_REG_VALUE, REG_RAX,           // ret
                //         IARG_END);
                // } else if (*rtnName == "memcpy") {  // memcpy use xmm registers to copy 
                //     RTN_InsertCall(
                //         rtn, IPOINT_BEFORE, (AFUNPTR)memcpy_point,
                //         IARG_ADDRINT, filter::entry,
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // dest
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // src
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                //         IARG_END);
                // } else if (*rtnName == "memmove") {//Also, a memory copy operation. However, the memmove() function can handle overlapping memory data
                //     RTN_InsertCall(
                //         rtn, IPOINT_BEFORE, (AFUNPTR)memmove_point,
                //         IARG_ADDRINT, filter::entry,
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // dest
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // src
                //         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                //         IARG_END);
                // }
            }
            rtn.Close();
        }
    }
}

FILE *files[3];

void Init() {
    // PIN_InitLock(&util::lock);
    files[0] = fopen(config::filenames[0], "w");
    files[1] = fopen(config::filenames[1], "w");
    files[2] = fopen(config::filenames[2], "w");
    logger::setInfo(config::flags[0], files[0]);//info文件同样记录了每个函数和指令，和debug的区别在于，普通指令以trace开头，taint指令以instruction开头
    logger::setBBL(config::flags[1], files[1]); //记录执行基本块
    logger::setBBLtrace(config::flags[2], files[2]);
}

void Fini(INT32 code, VOID *v) {
    printf("program end\n");
    fprintf(files[0], "#eof\n");
    fclose(files[0]);
    fprintf(files[1], "#eof\n");
    fclose(files[1]);
}

INT32 Usage() {
    printf("error\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[]) {
    std::cout<<"start"<<std::endl;
    if (PIN_Init(argc, argv)) return Usage();
    Init();
    /*Initialize symbol table code*/
    PIN_InitSymbols();
    PIN_InitLock(&util::lock);

    IMG_AddInstrumentFunction(Image, 0); /* Image-level Instrument*/
    /* Trace-level Instrument(no taint track, only extract loop)*/
    /* Instruction-level Instrument is involved*/
    TRACE_AddInstrumentFunction(Trace, 0); 
    
    logger::info("=================Time TO StartProgram===================\n");
    PIN_StartProgram();
    
    PIN_AddFiniFunction(Fini, 0);

    return 0;
}
