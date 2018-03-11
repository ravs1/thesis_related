#importing libraries
from sklearn.ensemble import RandomForestClassifier

from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
import pandas as pd
#import numpy as np
#import nltk
#import string
#import matplotlib.pyplot as plt
#import seaborn as sns
#from sklearn.feature_extraction.text import TfidfTransformer
#from sklearn.feature_extraction.text import TfidfVectorizer
#from sklearn.feature_extraction.text import CountVectorizer
#from sklearn import metrics
#from sklearn.metrics import confusion_matrix
#from sklearn.metrics import roc_curve,auc
#from sklearn.cluster import KMeans
#from nltk.stem.porter import PorterStemmer

#import re
#import string
#from nltk.corpus import stopwords
#from nltk.stem import PorterStemmer
#from nltk.stem.wordnet import WordNetLemmatizer

#using the mythril python library for disassembly
#https://github.com/ConsenSys/mythril
#takes bytecode and ouputs machine level opcodes

from mythril.ether import asm,util
import os
import json
import logging



class Disassembly:

    def __init__(self, code):
        self.instruction_list = asm.disassemble(util.safe_decode(code))
        self.xrefs = []
        self.func_to_addr = {}
        self.addr_to_func = {}

        try:
            mythril_dir = os.environ['MYTHRIL_DIR']
        except KeyError:
            mythril_dir = os.path.join(os.path.expanduser('~'), ".mythril")

        # Load function signatures

        signatures_file = os.path.join(mythril_dir, 'signatures.json')

        if not os.path.exists(signatures_file):
            logging.info("Missing function signature file. Resolving of function names disabled.")
            signatures = {}
        else:
            with open(signatures_file) as f:
                signatures = json.load(f)

        # Parse jump table & resolve function names

        jmptable_indices = asm.find_opcode_sequence(["PUSH4", "EQ"], self.instruction_list)

        for i in jmptable_indices:
            func_hash = self.instruction_list[i]['argument']
            try:
                func_name = signatures[func_hash]
            except KeyError:
                func_name = "_function_" + func_hash

            try:
                offset = self.instruction_list[i+2]['argument']
                jump_target = int(offset, 16)

                self.func_to_addr[func_name] = jump_target
                self.addr_to_func[jump_target] = func_name
            except:
                continue



    def get_easm(self):

        return asm.instruction_list_to_easm(self.instruction_list)



# loading data
df = pd.read_csv('/Users/ravishaggarwal/Desktop/contracts.csv', sep=',')

#source Ethereum yellow paper
EVM_OPCODE_SET = {'STOP', 'ADD', 'MUL', 'SUB', 'DIV', 'SDIV', 'MOD', 'SMOD', 'ADDMOD', 'MULMOD', 'EXP', 'SIGNEXTEND',
                 'LT','GT', 'SLT', 'SGT', 'EQ', 'ISZERO', 'AND', 'OR', 'XOR', 'NOT', 'BYTE','SHA3',
                 'ADDRESS', 'BALANCE', 'ORIGIN', 'CALLER', 'CALLVALUE', 'CALLDATALOAD', 'CALLDATASIZE', 'CALLDATACOPY',
                  'CODESIZE', 'CODECOPY', 'GASPRICE','EXTCODESIZE','EXTCODECOPY', 'RETURNDATASIZE', 'RETURNDATACOPY',
                 'BLOCKHASH', 'COINBASE', 'TIMESTAMP', 'NUMBER', 'DIFFICULTY', 'GASLIMIT','POP','MLOAD', 'MSTORE', 'MSTORE8'
                 'SLOAD', 'SSTORE', 'JUMP', 'JUMPI', 'PC', 'MSIZE', 'GAS', 'JUMPDEST','PUSH1','PUSH2','PUSH3','PUSH4',
                  'PUSH5','PUSH6','PUSH7','PUSH8','PUSH9','PUSH10','PUSH11','PUSH12','PUSH13','PUSH14','PUSH15','PUSH16',
                 'PUSH17','PUSH18','PUSH19','PUSH20','PUSH21','PUSH22','PUSH23','PUSH24','PUSH25','PUSH26','PUSH27',
                 'PUSH28','PUSH29','PUSH30','PUSH31','PUSH32','DUP1','DUP2','DUP3','DUP4','DUP5','DUP6','DUP7','DUP8','DUP9',
                 'DUP10','DUP11','DUP12','DUP13','DUP14','DUP15','DUP16','DUP17','DUP18','SWAP1','SWAP2','SWAP3','SWAP4',
                 'SWAP5','SWAP6','SWAP7','SWAP8','SWAP9','SWAP10','SWAP11','SWAP12','SWAP13','SWAP14','SWAP15','SWAP16',
                 'LOG0','LOG1','LOG2','LOG3','LOG4','CREATE', 'CAL', 'CALLCODE','RETURN','DELEGATECALL' ,'STATICCALL','REVERT',
                  'INVALID','SELFDESTRUCT'}


#print(df.head(5))
#translating the bytecodes to opcodes
opcodes = []
try:
    for i in df['result.code']:
        #print(i)
        desc = Disassembly(i)
        #desc.instruction_list
        #print(desc.get_easm())
        opcodes.append(desc.get_easm())
except:
    pass


source_words = []
try:
    for i in df_opcodes:
        source = i.split()
        source_words.append(source)
        #for w in source_words:
            #if (w in EVM_OPCODE_SET):
                #clean_ops_0.append(w)
except:
    pass

clean_ops = []
try:
    for w in source_words:
        if (w in EVM_OPCODE_SET):
            clean_ops.append(w)

except:
    pass

len(clean_ops)