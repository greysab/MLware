"""
Classification of malware types among Win32 EXE files with multinomial naive bayes .
Features computed are: Imports, InitializedDataSize, PE entry-point, UninitializedDataSize and Code Size  
Targets are malware names given by AV vendors
 
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
from collections import Counter
from sklearn.naive_bayes import MultinomialNB
 
#loads files in workingPath into memory     24695 FILES
def readData(workingPath):
    data=[]
    path, dirs, files = os.walk(workingPath).next()
    print "Loading ..."
    for filename in files:
        with open(workingPath+filename) as data_file:
             data.append(json.load(data_file))      
    return data
#Select Win32 EXE files and select among them commonly named malwares
#Use a pre computed list of most frequent malware :labels_list
#This list was obtained by running the agreed_name function on all files and then selecting the 10 most common malware types/names
#A naive analysis have been done to ensure that each name reprensent a different malware type and not a generation
#Features are then computed on each file and stored on disk 
def file2feature(data):
    target=[]
    EP=[]
    CS=[]
    Un=[]
    sec=[]
    dll=[]
    IDS=[]
    print "File to features..."
    labels_list=['Win32.Worm.Allaple.Gen', 'Gen:Adware.BrowseFox.1', 'Win32.Virtob.Gen.12', 'Trojan.Prepender.G','Win32.Sality.3', 'Win32.Ramnit.N', 'Win32.Parite.B', 'Gen:Variant.Kazy.667474', 'Trojan.VBRan.Gen.2','Win32.Expiro.Gen.2']
    for i in data:
        result=[]
        if i["type"]=="Win32 EXE":
            for k,v in i["scans"].items():
                if v["detected"]==True:
                    result.append(v["result"])
            label=agreed_name(result)
            features=["exiftool","pe-entry-point","imports","sections"]
            #if the malware name is common to +5 AV and it is one of 10 most frequent
            if isinstance(label, str) and label in labels_list:     
                if all(x in i["additional_info"] for x in features) and "InitializedDataSize" in i["additional_info"]["exiftool"]:
                    target.append(labels_list.index(label))
                    #features sections,imports,EP,InitializedDS,UninitializedDS,CS,
                    sec.append(len(i["additional_info"]["sections"]))
                    d=[]
                    for k,v in i["additional_info"]["imports"].items():
                        d.append(k.lower())
                    dll.append(d)       
                    EP.append(i["additional_info"]["pe-entry-point"])       
                    CS.append(int(i["additional_info"]["exiftool"]["CodeSize"]))
                    Un.append(int(i["additional_info"]["exiftool"]["UninitializedDataSize"]))
                    ids=int(i["additional_info"]["exiftool"]["InitializedDataSize"])
                    IDS.append(ids)
 
         
    enc_dll=encode_dll(dll)
    #Save to disk
    pickle.dump(CS, open( "CS_Win32EXE.p", "wb" ))
    pickle.dump(enc_dll, open( "DLL_Win32EXE.p", "wb" ))
    pickle.dump(Un, open( "Un_Win32EXE.p", "wb" ))
    pickle.dump(IDS, open( "IDS_Win32EXE.p", "wb" ))
    pickle.dump(EP, open( "EP_Win32EXE.p", "wb" ))
    pickle.dump(target, open( "Target_Win32EXE.p", "wb" ))
 
#Plots malware types count
def MalwarePlot(c):
    heights1=()
    names=[]
    for k,v in c:
        heights1=heights1+(v,)
        names.append(k)     
    #crop names length   
    names=[i[6:20] if i[:5]=="Win32" else i[:15] for i in names ]   
    x = tuple(n for n in np.arange(len(heights1)+1))
    fig, ax = plt.subplots()
    fig.suptitle('Malware types by AV vendors', fontsize=15)
    width = 0.4
    ax.bar(range(len(heights1)), heights1, label='Malware type', alpha=0.5, color='b')
    plt.xticks([i+width/2 for i in x], names)
    ax.set_ylabel('Count')
    plt.legend(loc='upper left')
    fig.set_size_inches(18, 9)
    plt.savefig('MalwareTypes.png')
 
def encode_dll(dll):
    #Encoding dlls imported to a binary matrix
    all_dlls= [j for i in dll for j in i]
    all_dlls=np.array(list(set(all_dlls)))
    dll_converted=[]
    #Matrix of presences
    for i in dll:
        line=np.zeros(len(all_dlls))
        for j in i:
            ind=np.array(np.where(all_dlls==j))[0]
            line[ind]=1
        dll_converted.append(line) 
    return np.array(dll_converted)  
 
#Given the target array return an array of indices matching classes with population above limit and 'limit' samples per class
def equalize_classes(target,limit):
    #Classes with population above the limit
    above_limit= [k for k,v in Counter(target).items() if v>limit ]
    #Extracting indices for this classes
    above_limit_ind=None
    target=np.array(target)
    for x in np.delete(above_limit,above_limit[0]):
        if above_limit_ind is None:
        above_limit_ind = np.array(np.where(target==above_limit[0]))[0][:limit] 
        if len(above_limit)==2:
           above_limit_ind= np.hstack((above_limit_ind,np.array(np.where(target==above_limit[x]))[0]))  
        else:
        above_limit_ind= np.hstack((above_limit_ind,np.array(np.where(target==above_limit[x]))[0][:limit] ))
    return above_limit_ind
 
 
#Given files features and targets, build a multiclassification naive bayes model to predict malware types
def classification(X,target,limit):
    X,target=shuffle(X,target)
    X_train, X_test, y_train, y_test = train_test_split(X, target, test_size=0.3)
    clf = MultinomialNB()
    clf.fit(X_train, y_train)
    labels=clf.predict(X_test)
    score = clf.score(X_test,y_test)
    print "Naive Bayes learning score: ",round(score,2)
    return labels
 
#If 5 or more vendors give a scanned malware the same name, returns this name and assign it as label to the Win32 exe file
#Running this function on all dataset resulted in 10 most common malware (names)
#'Win32.Worm.Allaple.Gen','Gen:Adware.BrowseFox.1','Win32.Virtob.Gen.12','Trojan.Prepender.G','Win32.Sality.3','Win32.Ramnit.N','Win32.Parite.B','Gen:Variant.Kazy.667474','Trojan.VBRan.Gen.2','Win32.Expiro.Gen.2'
def agreed_name(result):
    if Counter(data).most_common(1)[0][1]>=5:
        return  str(Counter(data).most_common(1)[0][0])
    else:
        return  0
 
def main():
    if not len(sys.argv[1:]) and not os.path.isfile("IDS_Win32EXE.p"):
        print "usage is : python multiclass_win32 -p your/path/to/meta/files/ -l 20 -f imports"
        sys.exit(0) 
    else:       
        limit=20
        features="imports"    
        try:
            opts, args = getopt.getopt(sys.argv[1:],"p:l:f:")
        except getopt.GetoptError as err:
            print str(err)
            print "usage is : python multiclass_win32 -p your/path/to/meta/files/ -l 20 -f imports"
        global feature
        for o,a in opts:      
            if o in ("-l"):
                limit=20
            elif o in ("-f"):
                features=a
            elif o in ("-p"):
                if os.path.exists(a):
                workingPath = a
                data=readData(workingPath)
                file2feature(data)
                else:
                print "Wrong Path"
                print "usage is : python multiclass_win32 -p your/path/to/meta/files/ -l 20 -f imports"
            else:
                assert False,"Unhandled Option"
    target=pickle.load(open( "Target_Win32EXE.p", "rb" ))
    above_limit_ind=equalize_classes(target,limit)
    target=np.array(target)[above_limit_ind]
 
    if features=="imports":
        dll=pickle.load(open( "DLL_Win32EXE.p", "rb" ))
        dll=dll[above_limit_ind]
        label=classification(dll,target,limit)
    else:
        CS=pickle.load(open( "CS_Win32EXE.p", "rb" ))
        Un=pickle.load(open( "Un_Win32EXE.p", "rb" ))
        IDS=pickle.load(open( "IDS_Win32EXE.p", "rb" ))
        EP=pickle.load(open( "EP_Win32EXE.p", "rb" ))
        #Scaling
        IDS=[float(i) for i in IDS]
        EP=[float(i) for i in EP]
        Un=[float(i) for i in Un]
        CS=[float(i) for i in CS]
        min_max_scaler = preprocessing.MinMaxScaler()
        EP=min_max_scaler.fit_transform(EP)
        IDS=min_max_scaler.fit_transform(IDS)
        Un=min_max_scaler.fit_transform(Un)
        CS=min_max_scaler.fit_transform(CS)
 
        CS=CS[above_limit_ind]
        Un=Un[above_limit_ind]
        EP=EP[above_limit_ind]
        IDS=IDS[above_limit_ind]
        label=classification(zip(CS,Un,EP,IDS),target,limit)
 
 
main()
