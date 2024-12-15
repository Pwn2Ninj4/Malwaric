import math

#get Shannon Entropy

def getEntropy(data):
                
                pvalue = dict(((chr(x), 0) for x in range(0, 256)))
                for byte in data:
                    pvalue[chr(byte)] +=1
                data_len = len(data)
                entropy = 0.0
                
                for i in pvalue:
                    if pvalue[i] == 0:
                        continue
                    p = float(pvalue[i] / data_len)
                    entropy -= p * math.log(p, 2)
                return entropy