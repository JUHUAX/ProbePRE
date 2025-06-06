#include <vector>
#include <map>
#include "pin.H"
#include "pinobject.hpp"
#include "util.hpp"

class Block {
public:

    Block() {}

    Block(uint64_t rsp, int id): _rsp(rsp), _id(id) {}

    void push(uint64_t head, size_t size) {
        blocks.push_back(std::make_pair(head, head + size));
    }

    bool valid(uint64_t head, size_t size, size_t n) {
        n = std::min(blocks.size(), n);
        for (size_t i = 0; i < n; ++i) {
            if (head == blocks[n - 1 - i].first ||  head + size == blocks[n - 1 - i].second) return true;
        }
        return false;
    }

    bool exist(uint64_t head, size_t size) {
        return valid(head, size, blocks.size());
    }

    uint64_t rsp() { return _rsp;}
    int id() {return _id;}

private:
    std::vector<std::pair<uint64_t, uint64_t> > blocks;
    uint64_t _rsp;
    int _id;
};

class BlockTrace {
public:
    BlockTrace() {}
    void push(uint64_t head, size_t size, uint64_t rsp, int id) {
        while (!functions.empty() && functions.back().first < rsp) {
            trace.erase(functions.back().second);
            functions.pop_back();
        }
        if (trace.count(id) == 0) {
            trace[id] = Block(rsp, id);
            functions.push_back(std::make_pair(rsp, id));
        }
        trace[id].push(head, size);
    }

    bool exist(uint64_t head, size_t size, int id) {
        if (trace.count(id) == 0) return false;
        return trace[id].exist(head, size);
    }

private: 
    std::map<int, Block> trace;
    std::vector<std::pair<uint64_t, int> > functions;
};

BlockTrace blocktrace;
std::set<uint64_t> loops;
std::set<uint64_t> bbl;

void LogBlock(uint64_t baseAddr, uint64_t head, size_t size, uint64_t rsp, int id) {
    if (blocktrace.exist(head, size, id)) {
        logger::info("LOOP\t0x%lx\t%lx\n", head, size);
        if(loops.count(head) == 0){
            loops.insert(head);
        }
    }
    //记录新增bbl
    if(bbl.count(head) == 0){
        bbl.insert(head);
        logger::BBL("BBL\t0x%lx\t%lx\n", head, size);
        logger::BBL("orgBBL\t0x%lx\t%lx\n", (head - baseAddr), size);
        logger::BBL("\n");
    }
    blocktrace.push(head, size, rsp, id);  

    //跟踪基本块
    logger::BBLtrace("BBL\t0x%lx\t%lx\n", head, size);
    logger::BBLtrace("orgBBL\t0x%lx\t%lx\n", (head - baseAddr), size);
    logger::BBLtrace("\n");

}

VOID Trace(TRACE trace, VOID *v) {
    RTN rtn = TRACE_Rtn(trace);
    if (!RTN_Valid(rtn)) return;
    bool plt = (RTN_Name(rtn).find("plt") != std::string::npos);
    if (plt) return;
    SEC sec = RTN_Sec(rtn);
    if (!SEC_Valid(sec)) return;
    IMG img = SEC_Img(sec);
    std::string imgName = IMG_Name(img);
    bool isMain = IMG_IsMainExecutable(img);
    bool isLib = filter::libs(imgName);
    if (!isMain && !isLib) return;
    // 获取加载模块的基址
    ADDRINT baseAddr = IMG_LowAddress(img);
    logger::BBL("BASE ADDR: %p\n", baseAddr);
    int id = RTN_Id(rtn);
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl=BBL_Next(bbl)) {
        uint64_t addr = BBL_Address(bbl);
        size_t size = BBL_Size(bbl);
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)LogBlock, 
                        IARG_ADDRINT, baseAddr,
                        IARG_ADDRINT, addr,
                        IARG_ADDRINT, size,
                        IARG_REG_VALUE, REG_RSP,
                        IARG_ADDRINT, id,
                        IARG_END);
    }
}