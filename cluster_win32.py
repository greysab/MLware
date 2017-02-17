"""
Clustering win32 files with unsupervised learning algorithms: Kmeans, MiniBatchKMeans and Gaussian Mixture Model.
Features computed are: size of the PE file, Number of sections, imports (dll) and suspicious API loaded
Different combinations of features and algorithms can be tested on the win32 files.
The silhouette_score is used to measure the clustering efficiency. 
"""
from __future__ import division
import random
import sys,os
import json
import numpy as np
import pefile  
import pickle
from sklearn import preprocessing, metrics
from sklearn.cluster import KMeans, MiniBatchKMeans
import getopt
from sklearn.mixture import GMM
import matplotlib.pyplot as plt
 
#Command line parsing
def usage():
        print "Clustering win32 files"
        print
        print "Usage: task1.py -f feature -a algorithm"
        print "-f       - features on what to build the learning model: size_num, size_num_api, imports,api_size,api_num,all"
        print "-a       - pick the clustering algorithm: Kmeans, MiniBatchKmeans, GMM"
        print
        print "-p       - path to the vtfiles_win32_20151113 decompressed directory ending with /"
        print
        print "Examples: "
        print "python task1.py -f all -a Kmeans -p /home/vtfiles_win32_20151113/"
    print "python task1.py -f size_api -a MiniBatchKmeans -p /home/vtfiles_win32_20151113/"
    print
        sys.exit(0)
 
#Function taken from pescanner.py distributed by Michael Ligh 2010
#Checks if API used belongs to well-known alerts
#Returns suspicious API in a given PE file
def check_imports(pe):
# suspicious APIs to alert on 
    alerts = ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'ReadProcessMemory','CreateProcess', 'WinExec', 'ShellExecute', 'HttpSendRequest', 'InternetReadFile', 'InternetConnect','CreateService', 'StartService']
    ret = []
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return ret
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in lib.imports:
                if (imp.name != None) and (imp.name != ""):
                    for alert in alerts:
                        if imp.name.startswith(alert):
                            ret.append(imp.name)
        return ret
 
#Load Win32 files, for each file extract imported dll, file size, number of sections and a boolean array which a factor of suspicious API loaded. Features are serielized in separate files with pickle
def file2feature(workingPath):
    print "Files to features..."
    dll=[]
    size=[]
    num=[]
    suspectedAPI=[]
    path, dirs, files = os.walk(workingPath).next()
    rand_files=random.sample(files, 1000)
    for filename in rand_files:
        tmp=[]
        pe =  pefile.PE(workingPath+filename)
        pe.parse_data_directories()
        c=check_imports(pe)
        #if the current file contains suspicious API loaded, compute rate over 13 known alerts
        if c:
            suspectedAPI.append(round(len(c)/13,2))
        else:
            suspectedAPI.append(0)
        #Number of sections in the pe file
        num.append(pe.FILE_HEADER.NumberOfSections)
        #Retreive imported dll 
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                tmp.append((entry.dll).lower())
            dll.append(np.unique(tmp))
        else:
            dll.append([])
        #PE size
        size.append(os.path.getsize(workingPath+filename))
    #Save features computed
    pickle.dump(num, open( "numSec.p", "wb" ))
    pickle.dump(dll, open( "dll.p", "wb" ))
    pickle.dump(size, open("size.p", "wb" ))
    pickle.dump(suspectedAPI, open("api.p", "wb" ))
     
 
#Cluster files using features computed with selected learning algorithms
#Returns labels assigned to files 
def clustering(train,algo):
    print "Clustering files..."
    #Cluster with KMEANS
    if algo=="Kmeans":
        kmeans = KMeans(n_clusters=2,random_state=1)
        kmeans.fit(train)
        labels = kmeans.labels_
        print("Silhouette Coefficient: %0.3f "% metrics.silhouette_score(train, labels, metric='sqeuclidean'))
        return labels
    elif algo=="MiniBatchKmeans":
    #Cluster with Mini Batch KMEANS
        km = MiniBatchKMeans(n_clusters=2, batch_size=5000)
        km.fit(train)
        labels= km.labels_
        print("Silhouette Coefficient: %0.3f"
              % metrics.silhouette_score(train, labels, metric='sqeuclidean'))
        return labels
    #Cluster with Gaussian mixture model    
    elif algo=="GMM":
        classifiers = dict((covar_type, GMM(n_components=2,
                    covariance_type=covar_type, init_params='wc', n_iter=20))
                   for covar_type in ['spherical', 'diag', 'tied', 'full'])
        best=0
        for index, (name, classifier) in enumerate(classifiers.items()):
             classifier.fit(train)
             labels = classifier.predict(train)
             if best<metrics.silhouette_score(train, labels, metric='sqeuclidean'):
                best=metrics.silhouette_score(train, labels, metric='sqeuclidean')
                bname=name
        print("Silhouette Coefficient with %s %0.3f"
              %(bname,best)) 
        return labels
 
def main(): 
    workingPath=None
    if not len(sys.argv[1:]):
                  usage()
    show="false"             
    try:
        opts, args = getopt.getopt(sys.argv[1:],"f:a:s:p:")
    except getopt.GetoptError as err:
        print str(err)
        usage()
    global feature
    for o,a in opts:
               
                  if o in ("-f"):
                          feature=a
                  elif o in ("-a"):
                          algo = a
                  elif o in ("-s"):
                          show = a.lower()
                  elif o in ("-p"):
                  if os.path.exists(a):
                              workingPath = a
                  else:
                      print "Wrong Path"
                      usage()
                  else:
                          assert False,"Unhandled Option"
    #Fisrt we compute features from win32 folder than save them for clustering
    if not workingPath and not os.path.isfile("api.p"):
        print "#Path to Win32 files is mandatory\n"
        usage()
    #If features are not computed yet
    if workingPath: 
        file2feature(workingPath)
    print "Loading, scaling and selecting features..."
    #Load rate of suspected API 
    api=pickle.load(open( "api.p", "rb" ))
 
    #Scaling SIZE
    size = pickle.load(open( "size.p", "rb" ))
    size=[float(i) for i in size]
    min_max_scaler = preprocessing.MinMaxScaler()
    size=min_max_scaler.fit_transform(size)
 
    #Scaling NumberOfSections
    num=pickle.load(open( "numSec.p", "rb" ))
    num=[float(i) for i in num]
    num=min_max_scaler.fit_transform(num)
 
    #Loading dlls
    dll=pickle.load(open( "dll.p", "rb" ))
     
    #Size and NumberOfSequence spread ajusting
    bigSize=np.array(np.where(size>0.1))[0]
    size=np.delete(size,bigSize)
    dll=np.delete(dll,bigSize)
    api=np.delete(api,bigSize)
    num=np.delete(num,bigSize)
 
    bigNum=np.array(np.where(num>0.5))[0]
    num=np.delete(num,bigNum)
    dll=np.delete(dll,bigNum)
    api=np.delete(api,bigNum)
    size=np.delete(size,bigNum)
 
    ########################################"
 
    #Select features to perform clustering
    if feature=="size_num":
        data=np.array(zip(size,num))
    elif feature=="size_num_api":
        data=np.array(zip(size,num,api))
    elif feature=="num_api":
        data=np.array(zip(api,num))
    elif feature=="size_api":
        data=np.array(zip(api,size))
    elif feature=="all" or feature=="imports":
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
        if feature=="all":
            for i in range(len(dll_converted)):
                dll_converted[i]=np.hstack((dll_converted[i],size[i],num[i],api[i]))
            data=np.array(dll_converted)
        else: 
            data=np.array(dll_converted)
    else:
        print "Unhandled Feature"
        usage()
    labels=clustering(data,algo)
    print labels
    if show=="true" and feature!="all" and feature!="imports" and feature.count("_")==1:
        f1=feature.split("_", 2)[0]
        f2= feature.split("_", 2)[1]
        plot(labels,eval(f1),eval(f2)) 
    if show=="true" and feature.count("_")==2:
        plot3D(labels,api,size,num)
 
 
def plot(labels,f1,f2):
    global feature
    for c, m, l  in [('g', 's', 0), ('b', 'o', 1)]:
        labelsP=np.array(np.where(labels==l))[0]    
        x=[]
        y=[]
        for i in labelsP:
            x.append(f1[i])
            y.append(f2[i])
        plt.scatter(x, y, c=c, marker=m)
    plt.xlabel(feature.split("_", 2)[0], fontsize=18)
    plt.ylabel(feature.split("_", 2)[1], fontsize=18)
    plt.show()
def plot3D(labels,f1,f2,f3):
    from mpl_toolkits.mplot3d import Axes3D
    fig = plt.figure()
    ax = fig.add_subplot(111, projection='3d')
    for c, m, l  in [('b', 'o', 0), ('r', '^', 1)]:
        labelsP=np.array(np.where(labels==l))[0]
        x=[]
        y=[]
        z=[]
        for i in labelsP:
            x.append(f1[i])
            y.append(f2[i])
            z.append(f3[i])
        ax.scatter(x, y, z, c=c, marker=m)
 
    ax.set_xlabel('Api')
    ax.set_ylabel('Size')
    ax.set_zlabel('Num Seq')
    ax.text2D(0.05, 0.95, "Clustering Win32 files", transform=ax.transAxes)
    plt.show()
 
main()
