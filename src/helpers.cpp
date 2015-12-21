#include <ida.hpp>
#include <idp.hpp>
#include <funcs.hpp>
#include <gdl.hpp>

#include <vector>

using namespace std;

#ifdef __cplusplus
extern "C" {
#endif

qflow_chart_t * qflow_chart_create(char * title, func_t * pfn, ea_t ea1, ea_t ea2,
                        int flags){
    qflow_chart_t * qc = new qflow_chart_t();
    qc->create(title, pfn, ea1, ea2, flags);
    return qc;
}

void qflow_chart_release(qflow_chart_t * qc){
  if(qc)
    delete qc;
}

void get_func_items(func_t * pfn, ea_t ea, ea_t ** pret, int * psize){
  // TODO make smthg more efficient than vector
  vector<ea_t> result = vector<ea_t>();
  func_item_iterator_t fii;
  ea_t * ret = 0;
  int size = 0;

  *psize = size;
  *pret = ret;

  for (bool ok = fii.set(pfn, ea); ok; ok=fii.next_code()){
    result.push_back(fii.current());
  }
  size = result.size();
  ret = (ea_t *)malloc(size * sizeof(ea_t) + 1);

  for(int i = 0; i < size; i++){
    ret[i] = result[i];
  }
  *psize = size;
  *pret = ret;
}

int qflow_chart_size(qflow_chart_t * qc){
  return qc->blocks.size();
}

qbasic_block_t * qflow_chart_get_block(qflow_chart_t * qc, int i){
  return &qc->blocks[i];
}

void get_intseq_items(intseq_t * is, int ** pret, int * psize){
  // TODO add nullptr checks
  int size = is->size();
  int * ret = (int *)malloc(size * sizeof(int) + 1);

  *psize = size;
  *pret = ret;

  for (int i = 0; i < size; i++)
    ret[i] = (*is)[i];
}


#ifdef __cplusplus
}
#endif
