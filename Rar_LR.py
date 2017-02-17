"""
Classification of .Rar files with logistic regression.
Features computed are: ratio of CompressedSize/UncompressedSize of the RAR and weighted rate of ArchivedFileName 
Target is equal to 1 if number of positives votes are superior to 0, and equal to 0 otherwise. 
"""
from __future__ import division
import json,os,sys,getopt
import numpy as np
from matplotlib.pyplot import plot, show
import matplotlib.pyplot as plt
import pickle
from sklearn import linear_model
from sklearn.cross_validation import train_test_split
from sklearn.utils import shuffle
from collections import Counter
 
#loads files in workingPath into memory
def readData(workingPath):
    data=[]
    path, dirs, files = os.walk(workingPath).next()
    print "Loading ..."
    for filename in files:
        with open(workingPath+filename) as data_file:
             data.append(json.load(data_file)) 
    print len(data)     
    return data
 
#Computes features on each loaded RAR file
#Features are: ratio of compressed and uncompressed file size and a weighted suspicious extention rate computed in function SuspiciousRate(data)
def file2feature(data):
    SizeRatio=[]
    target=[]
    ExtRates=[]
    print "Files to features..."
    for i in data:
        if i["type"]=="RAR":
            target.append(1 if i["positives"] >0 else 0)
            if "exiftool" in i["additional_info"] and "ArchivedFileName" in i["additional_info"]["exiftool"]: 
                #Extract file extention 
                ext= i["additional_info"]["exiftool"]["ArchivedFileName"]
                ext=ext[len(ext)-3:]
                if ext=="exe":
                    rate=0.8
                    cpt+=1
                if i["positives"] >0: 
                    t+=1
                elif ext=="html" or ext=="dll":
                    rate=0.4
                elif ext=="zip" or ext=="hex":
                    rate=0.2
                else:
                    rate=0
                ExtRates.append(rate)
                if "CompressedSize" in i["additional_info"]["exiftool"] and "UncompressedSize" in i["additional_info"]["exiftool"]:
                    un=float(i["additional_info"]["exiftool"]["UncompressedSize"])
                    c= float(i["additional_info"]["exiftool"]["CompressedSize"])
                    if un!=0:
                        SizeRatio.append(round(c/un,3))
                    else:
                        SizeRatio.append(0)                 
                else:
                    SizeRatio.append(0)                 
            else:
                SizeRatio.append(0)                 
                ExtRates.append(0)
     
    #Save features      
    pickle.dump(SizeRatio, open( "SizeRatio_RAR.p", "wb" ))
    pickle.dump(ExtRates, open( "ExtRates_RAR.p", "wb" ))
    pickle.dump(target, open( "Target_RAR.p", "wb" ))
#Given files features and targets, build a classification model to predict files labels
def classification(f1,f2,target):
    X=zip(f1,f2)
    X,target=shuffle(X,target)
    X_train, X_test, y_train, y_test = train_test_split(X, target, test_size=0.2)
    logistic = linear_model.LogisticRegression()
    logistic.fit(X_train, y_train)
    score=logistic.score(X_test, y_test)
    labels= logistic.predict(X_test)
    print 'LogisticRegression score:',round(score,2 )
    return labels,X_test
#Shows 2D classification
def plot(labels,f1,f2):
    for c, m, l  in [('b', 'o', 0), ('r', '^', 1)]:
        labelsP=np.array(np.where(labels==l))[0]    
        x=[]
        y=[]
        for i in labelsP:
            x.append(f1[i])
            y.append(f2[i])
        plt.scatter(x, y, c=c, marker=m)
    plt.xlabel("Size Ratio", fontsize=18)
    plt.ylabel("Weighted extention", fontsize=18)
    plt.savefig('RAR.png')
    plt.show()
#Returns a dictionary of suspicious files rates 
#dic["Win32 EXE"] is the proportion of Win32 EXE virus among all other files
def SuspiciousRate(data):
    virusTypes=[i["type"] for i in data if i["positives"]>0]
    d= Counter(virusTypes)
    return {k:round(v/len(data),4) for (k,v) in d.items()}
 
def main():
    if not len(sys.argv[1:]) and not os.path.isfile("SizeRatio_RAR.p"):
        print "usage is : python classifier_Rar -p your/path/to/meta/files/ -s true"
        print "Please spicifie meta files path directory"
        sys.exit(0) 
    show="False"             
    try:
        opts, args = getopt.getopt(sys.argv[1:],"p:s:")
    except getopt.GetoptError as err:
        print str(err)
        print "usage is : python classifier_Rar -p your/path/to/meta/files/ -s true"   
    global feature
    for o,a in opts:      
        if o in ("-s"):
            show = a.lower()
        elif o in ("-p"):
            if os.path.exists(a):
                workingPath = a
            data=readData(workingPath)
            file2feature(data)
            else:
            print "Wrong Path"
            print "usage is : python classifier_Rar -p your/path/to/meta/files -s true"
        else:
            assert False,"Unhandled Option"
    #To visualize different malicious files type proportions
#   rates=SuspiciousRate(data)
#   print rates
#   print dict((k, v) for k, v in rates.items() if v >0.0002)
    #Loading features
    SR=pickle.load(open( "SizeRatio_RAR.p", "rb" ))
    Ext=pickle.load(open( "ExtRates_RAR.p", "rb" ))
    target=pickle.load(open( "Target_RAR.p", "rb" ))
    target=np.array(target)
    Ext=np.array(Ext)
    SR=np.array(SR)
    #Classification
    labels,x_test=classification(SR,Ext,target)
    if show=="true":
        plot(labels,x_test[:,0],x_test[:,1])
main()
