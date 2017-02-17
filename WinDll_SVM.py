"""
Classification of Win32 DLL files with support machines vector.
Features computed are: InitializedDataSize and PE entry-point  
Target is equal to 1 if number of positives votes are superior to 0, and equal to 0 otherwise. 
"""
from __future__ import division
import json,os,sys,getopt
import numpy as np
from matplotlib.pyplot import plot, show
import matplotlib.pyplot as plt
import pickle
from sklearn import preprocessing
from sklearn import svm
from sklearn import grid_search
from sklearn.cross_validation import train_test_split
from sklearn.utils import shuffle
#loads files in workingPath into memory
def readData(workingPath):
    data=[]
    path, dirs, files = os.walk(workingPath).next()
    print "Loading ..."
    for filename in files:
        with open(workingPath+filename) as data_file:
             data.append(json.load(data_file))      
    return data
#Win32 DLL
#Computes features on each loaded Win32 DLL
#Features are: InitializedDataSize and pe-entry-point
def file2feature(data):
    IDS=[]
    target=[]
    EP=[]
    CS=[]
    Un=[]
    print "File to features..."
    for i in data:
        if i["type"]=="Win32 DLL":
            #Targets
            target.append(1 if i["positives"] >0 else 0) 
            #InitializedDataSize
            if "exiftool" in i["additional_info"] and"InitializedDataSize" in i["additional_info"]["exiftool"] :
                CS.append(int(i["additional_info"]["exiftool"]["CodeSize"]))
                Un.append(int(i["additional_info"]["exiftool"]["UninitializedDataSize"]))
                ids=int(i["additional_info"]["exiftool"]["InitializedDataSize"])
                IDS.append(ids)
            else:
                IDS.append(0)
                CS.append(0)
                Un.append(0)
            #pe-entry-point
            if "pe-entry-point" in i["additional_info"]:
                EP.append(i["additional_info"]["pe-entry-point"])       
            else:
                EP.append(0)
    #Save to disk
    pickle.dump(CS, open( "CS_Win32Dll.p", "wb" ))
    pickle.dump(Un, open( "Un_Win32Dll.p", "wb" ))
    pickle.dump(IDS, open( "IDS_Win32Dll.p", "wb" ))
    pickle.dump(EP, open( "EP_Win32Dll.p", "wb" ))
    pickle.dump(target, open( "Target_Win32Dll.p", "wb" ))
 
#Given files features and targets, build an SVM model to predict files labels
def classification(f1,f2,f3,f4,target):
    X=zip(f1,f2,f3,f4)
    X,target=shuffle(X,target)
    X_train, X_test, y_train, y_test = train_test_split(X, target, test_size=0.3)
    clf = svm.SVC()
    clf.fit(X_train, y_train)
    labels= clf.predict(X_test)
    score = clf.score(X_test,y_test)
    print "SVM score: ",round(score,2)
    return labels,X_test
#Show 2D classification obtained
def plot_labels(labels,f1,f2):
    for c, m, l  in [('b', 'o', 0), ('r', '^', 1)]:
        labelsP=np.array(np.where(labels==l))[0]    
        x=[]
        y=[]
        for i in labelsP:
            x.append(f1[i])
            y.append(f2[i])
        plt.scatter(x, y, c=c, marker=m)
    plt.xlabel("IDS", fontsize=18)
    plt.ylabel("CS", fontsize=18)
    plt.savefig('tst.png')
    plt.show()
 
def main():
    if not len(sys.argv[1:]) and not os.path.isfile("IDS_Win32Dll.p"):
        print "usage is : python classifier_Win32Dll -p your/path/to/meta/files/ -s true"
        sys.exit(0) 
    show="False"             
    try:
        opts, args = getopt.getopt(sys.argv[1:],"p:s:")
    except getopt.GetoptError as err:
        print str(err)
        print "usage is : python classifier_Win32Dll -p your/path/to/meta/files/ -s true"  
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
            print "usage is : python classifier_Win32Dll -p your/path/to/meta/files/ -s true"  
        else:
            assert False,"Unhandled Option"
    #Loading features
    CS=pickle.load(open( "CS_Win32Dll.p", "rb" ))
    Un=pickle.load(open( "Un_Win32Dll.p", "rb" ))
    IDS=pickle.load(open( "IDS_Win32Dll.p", "rb" ))
    EP=pickle.load(open( "EP_Win32Dll.p", "rb" ))
    target=pickle.load(open( "Target_Win32Dll.p", "rb" ))
 
    #Scaling and variance ajusting
    IDS=[float(i) for i in IDS]
    EP=[float(i) for i in EP]
    Un=[float(i) for i in Un]
    CS=[float(i) for i in CS]
    min_max_scaler = preprocessing.MinMaxScaler(feature_range=(0, 5000))
    cpt=0
    while cpt<3:
        for i in ['EP','IDS']:
            big=np.array(np.where(eval(i)==max(eval(i))))[0]
            EP=np.delete(EP,big)
            IDS=np.delete(IDS,big)
            target=np.delete(target,big)
            Un=np.delete(Un,big)
            CS=np.delete(CS,big)
        cpt+=1
    EP=min_max_scaler.fit_transform(EP)
    IDS=min_max_scaler.fit_transform(IDS)
    Un=min_max_scaler.fit_transform(Un)
    CS=min_max_scaler.fit_transform(CS)
    #Classification
    labels,x_test=classification(IDS,EP,CS,Un,target)
    if show=="true":
        #IDS and CS
        plot_labels(labels,x_test[:,0],x_test[:,2])
 
main()
