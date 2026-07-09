
import random
import os
import hashlib
import binascii
import sys
import encoding
import cProfile,time
import threading
from ecc import point_add, scalar_mult, curve
# Path hack
sys.path.insert(0, os.path.abspath('.'))
sys.path.insert(1, os.path.abspath('..'))
from fhipe.fhipe import ipe

class KeyAuthority:
  readingsKeys,pTypeKeys,cTypeKeys = [],[],[]
  DecKey,pTypeDecKey,cTypeDecKey,rDecKey = 0 ,0, 0, 0
  pp, sk = 0,0

  def getReadingsEncryptionKeys(self):
    for i in range(0,numberOfPeriods):
      n = int.from_bytes(os.urandom(4), byteorder="big")
      KeyAuthority.readingsKeys.append(n)
    #print("Secret meter reading keys are: ",KeyAuthority.readingsKeys)
    return KeyAuthority.readingsKeys

  def getDecryptionKey(self,decPKeyHelper,decCKeyHelper,u):
    KeyAuthority.DecKey = self.getReadingsDecryptionKey() + self.getPTypeDecryptionKey(decPKeyHelper,u) + self.getCTypeDecryptionKey(decCKeyHelper,u)
    print("Decryption key is: ", KeyAuthority.DecKey)
    return KeyAuthority.DecKey

  def getReadingsDecryptionKey(self):
    KeyAuthority.rDecKey=0
    for i in range(0,numberOfPeriods):
      KeyAuthority.rDecKey += KeyAuthority.readingsKeys[i] * TP[i]
      KeyAuthority.rDecKey = KeyAuthority.rDecKey % pow(2,23)
    #print("Decryption key is: ", KeyAuthority.rDecKey)
    return KeyAuthority.rDecKey

  def getPTypeEncryptionKeys(self):
    for i in range(0,numberOfPeriods):
      n = int.from_bytes(os.urandom(4), byteorder="big")
      KeyAuthority.pTypeKeys.append(n)
    #print("Secret p type keys are: ",KeyAuthority.pTypeKeys)
    return KeyAuthority.pTypeKeys

  def getPTypeDecryptionKey(self,decPKeyHelper,u):
    KeyAuthority.pTypeDecKey = 0
    for i in range(0,numberOfPeriods):
      KeyAuthority.pTypeDecKey += decPKeyHelper[i] * KeyAuthority.pTypeKeys[i] * (FiT[i] - TP[i]) * (ZonesInfo[usersTupples[u][i][3]][i][0] * ZonalDeviationWeight[i]/ZonesInfo[usersTupples[u][i][3]][i][1])
      KeyAuthority.pTypeDecKey = KeyAuthority.pTypeDecKey % pow(2,23)
    #print("Decryption key is: ", KeyAuthority.pTypeDecKey)
    return KeyAuthority.pTypeDecKey

  def getCTypeEncryptionKeys(self):
    for i in range(0,numberOfPeriods): #10 periods
      n = int.from_bytes(os.urandom(4), byteorder="big")
      KeyAuthority.cTypeKeys.append(n)
    #print("Secret c type keys are: ",KeyAuthority.cTypeKeys)
    return KeyAuthority.cTypeKeys

  def getCTypeDecryptionKey(self,decCKeyHelper,u):
    KeyAuthority.cTypeDecKey = 0
    for i in range(0,numberOfPeriods):
      KeyAuthority.cTypeDecKey += decCKeyHelper[i] * KeyAuthority.cTypeKeys[i] * (RP[i] - TP[i]) * (ZonesInfo[usersTupples[u][i][3]][i][0] * ZonalDeviationWeight[i]/ZonesInfo[usersTupples[u][i][3]][i][2])
      KeyAuthority.cTypeDecKey = KeyAuthority.cTypeDecKey % pow(2,23)
    #print("Decryption key is: ", KeyAuthority.cTypeDecKey)
    return KeyAuthority.cTypeDecKey

  def ipeSetup(self):
    (KeyAuthority.pp, KeyAuthority.sk) = ipe.setup(D)

  def getSecretKey(self):
    return KeyAuthority.sk

  def getPublicParameters(self):
     return KeyAuthority.pp

class SmartMeter:
  def __init__(self):
    self.KAuth = KeyAuthority()
    self.sky = [[[[0 for _ in range(numberOfPeriods)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
    self.randomKeys = []

  def init(self):
    self.randomKeys = self.KAuth.getReadingsEncryptionKeys()

  def getMaskedReadings(self,u,i):
    return usersTupples[u][i][0] + self.randomKeys[i]

  # Pedersen Commitment
  def getCommitedReadings(self,u,i):
    return point_add(scalar_mult(usersTupples[u][i][0],curve.g),scalar_mult(5,curve.g))

  # InnerProducts functionl encryption (meater reading)
  def getIpfeEncryptedReading(self,u,i):
      for j in range(N): # N vectors per meter reading
        self.sky[i][j]= ipe.keygen(self.KAuth.getSecretKey(), encoding.VectorYEncoding(usersTupples[u][i][0],D)[j])
      return self.sky[i]

class MarketOperator:
  def __init__(self):
      self.KAuth = KeyAuthority()
      self.skxL = [[[[0 for _ in range(numberOfPeriods)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
      self.skxR = [[[[0 for _ in range(numberOfPeriods)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
      self.pRandomKeys,self.cRandomKeys = [],[]

  def init(self):
      self.pRandomKeys = self.KAuth.getPTypeEncryptionKeys()
      self.cRandomKeys = self.KAuth.getCTypeEncryptionKeys()

  # mask type of participation (P vector)
  def getMaskedPTypes(self,u,i):
    return usersTupples[u][i][2] + self.pRandomKeys[i] #prosumers encoding: 1 for prosumer and 0 for consumer

  # mask type of participation (C vector)
  def getMaskedCTypes(self,u,i):
    return 1 - usersTupples[u][i][2]+ self.cRandomKeys[i] #consumers encoding: 0 for prosumer and 1 for consumer

  def getComittedAmounts(self,u,i):
    return point_add(scalar_mult(-1 * usersTupples[u][i][1],curve.g),scalar_mult(7,curve.g))

  # InnerProducts functionl encryption (bid volumes)
  def getIpfeEncryptedVolume(self,u,i):
#      self.EncodedVolumesL,self.EncodedVolumesR = encoding.VectorXLEncoding(5,D),encoding.VectorXREncoding(5,D)
          if usersTupples[u][i][2]==1:
              for j in range(N):
                  self.skxL[i][j]= ipe.encrypt(self.KAuth.getSecretKey(), encoding.VectorXLEncoding(usersTupples[u][i][1],D)[j])
                  self.skxR[i][j]= ipe.encrypt(self.KAuth.getSecretKey(), encoding.VectorXREncoding(usersTupples[u][i][1],D)[j])
          else: # check if the user is a consumer, flip the two X vectors over to get a correct less than , greater than comparision for the negative values (as we simply have either two positve values or two negatvie values to compare)
               for j in range(N):
                   self.skxL[i][j]= ipe.encrypt(self.KAuth.getSecretKey(), encoding.VectorXREncoding(usersTupples[u][i][1],D)[j])
                   self.skxR[i][j]= ipe.encrypt(self.KAuth.getSecretKey(), encoding.VectorXLEncoding(usersTupples[u][i][1],D)[j])
          return self.skxL[i],self.skxR[i]

class Supplier:
  def __init__(self):
        self.BillCT, self.maskedReadings, self.maskedPTypes, self.maskedCTypes = [0 for _ in range(numberOfUsers)],[0 for _ in range(numberOfPeriods)],[0 for _ in range(numberOfPeriods)],[0 for _ in range(numberOfPeriods)]
        self.EncryptedReading = [[[[0 for _ in range(numberOfPeriods)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
        self.EncryptedVolumeL = [[[[0 for _ in range(numberOfPeriods)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
        self.EncryptedVolumeR = [[[[0 for _ in range(numberOfPeriods)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
        self.decPKeyHelper, self.decCKeyHelper= [[0 for _ in range(numberOfPeriods)] for _ in range(numberOfUsers)],[[0 for _ in range(numberOfPeriods)]for _ in range(numberOfUsers)]
        self.ComittedReadings,self.ComittedAmounts = [0 for _ in range(numberOfPeriods)],[0 for _ in range(numberOfPeriods)]
        self.DecKey= 0
        self.SM = SmartMeter()
        self.KAuth = KeyAuthority()
        self.MO = MarketOperator()
        self.agg = (0,0)

  def init(self):
      self.SM.init()
      self.MO.init()

  # Evaluate SM computation per trading period
  def getSMEncryptedData(self,u,i):
      start_time = time.time()
      self.EncryptedReading[i] = self.SM.getIpfeEncryptedReading(u,i)
      end_time = time.time()
      print("Encrypting encoded meter reading using IPFE computation time = ", end_time  -  start_time)
      start_time = time.time()
      self.maskedReadings[i] = self.SM.getMaskedReadings(u,i)
      end_time = time.time()
      print("Masking meter reading computation time = ", end_time  -  start_time)
      start_time = time.time()
      self.ComittedReadings[i]= self.SM.getCommitedReadings(u,i)
      end_time = time.time()
      print("Commiting to meter reading computation time  = ", end_time  -  start_time)

  # Evaluate a user (to be forwarded by LEMO) computation per trading period
  def getLEMOEncryptedData(self,u,i):
        start_time = time.time()
        self.EncryptedVolumeL[i],self.EncryptedVolumeR[i] = self.MO.getIpfeEncryptedVolume(u,i)
        end_time = time.time()
        print("Encrypting encoded trading volume using IPFE computation time = ", end_time  -  start_time)
        start_time = time.time()
        self.maskedPTypes[i] = self.MO.getMaskedPTypes(u,i)
        end_time = time.time()
        print("Masking first vector of participation type computation time = ", end_time  -  start_time)
        start_time = time.time()
        self.maskedCTypes[i] = self.MO.getMaskedCTypes(u,i)
        end_time = time.time()
        print("Masking second vector of participation type computation time = ", end_time  -  start_time)
        self.ComittedAmounts[i]= self.MO.getComittedAmounts(u,i)
        end_time = time.time()
        print("Commiting to meter reading computation time  = ", end_time  -  start_time)

  def getDecKey(self,u):
      self.DecKey = self.KAuth.getDecryptionKey(self.decPKeyHelper[u], self.decCKeyHelper[u],u)

  # Check if user has deviated using IPFE
  def checkDeviations(self,i):
      for j in range(N): # i: period number,  self.EncryptedReading[i] to retreive the encrypted reading of period i.
           #j: every meter reading is represented using N number of encdoed vectors , each is encrypted using IPFE
      # Less than comparision , check if trading volume is less than the actual meter reading (positive deviation)
          prod = ipe.decrypt(self.KAuth.getPublicParameters(), self.EncryptedReading[i][j] , self.EncryptedVolumeL[i][j], D)
          if prod==0:return 1 # indicate positive deviation
      # Greater than comparision , check if trading volume is more than the actual meter reading (negative deviation)
          prod = ipe.decrypt(self.KAuth.getPublicParameters(),self.EncryptedReading[i][j],  self.EncryptedVolumeR[i][j], D)
          if prod==0:return -1 # indicate negative deviation
      return 0 # No deviation, trading volume is equal to meater reading

  # supplier computes indivudal bill per trading period
  def ComputeBill(self,u,i):
        dev = self.checkDeviations(i)
#   self.BillCT += ((maskedReadings[i] * TP[i]) + ((totalDeviation[i]>0) * (self.checkDeviations(i)>0) * maskedPTypes[i] * totalDeviation[i] *(FiT[i] - TP[i])) + ((totalDeviation[i]<0) * (self.checkDeviations(i)<0) * maskedCTypes[i] * totalDeviation[i] *(RP[i] - TP[i])))
        self.BillCT[u] += self.maskedReadings[i] * TP[i]
        if (totalDeviation[i]>0) and (ZonesInfo[usersTupples[u][i][3]][i][0]>0) and (dev >0):
            self.decPKeyHelper[u][i]=1
            self.BillCT[u] += self.maskedPTypes[i] * (ZonesInfo[usersTupples[u][i][3]][i][0] * ZonalDeviationWeight[i]/ZonesInfo[usersTupples[u][i][3]][i][1]) *(FiT[i] - TP[i]) # if it is a consumer, then this added value would be removed during decryption
        elif (totalDeviation[i]<0) and (ZonesInfo[usersTupples[u][i][3]][i][0]<0) and (dev<0):
            self.decCKeyHelper[u][i]=1
            self.BillCT[u] += self.maskedCTypes[i] * (ZonesInfo[usersTupples[u][i][3]][i][0] * ZonalDeviationWeight[i]/ZonesInfo[usersTupples[u][i][3]][i][2]) *(RP[i] - TP[i]) # if it is a prosumer, then this added value would be removed during decryption

  def decryptBill(self,u):
    self.BillCT[u]=self.BillCT[u] % pow(2,23)
    print("Encrypted bill for user (", u ,") is: ", self.BillCT[u])
    Bill = (self.BillCT[u] - self.DecKey) % pow(2,23)
    print("The bill after decryption is: ", Bill)

  #Compute individual deviations commitmements and add it to the previus IV commitmnts
  def computeIVCommitment(self,u,i):
      if i ==0:
          self.agg = point_add(self.ComittedAmounts[i],self.ComittedReadings[i])
      else:
          Iv = point_add(self.ComittedAmounts[i],self.ComittedReadings[i])
          self.agg = point_add(self.agg,Iv)

  #Verify correctness of IV commitmements
  def checkIVCommitments(self,u):
    Result = 0
    for i in range(0,numberOfPeriods):
        Result += (usersTupples[u][i][0] + (-1 * usersTupples[u][i][1]))
    #R = randomKeys[0] + randomKeys[0]
    # Should get agg2 value from MPC
    agg2 = point_add(scalar_mult(Result ,curve.g),scalar_mult(24,curve.g))
    print ("\nComparsision result...")
    if (self.agg[0]==agg2[0]):
    	print ("Success. Individual deviations are correct.\n....................................")
    else:
    	print ("Failure!")

''' --------------------------------------------------------------------------------------------------'''

TP = [156,201,233,160,247,210,195,262,187,143] 
FiT = [100,90,95,100,100,99,97,95,98,99]
RP = [290,300,295,285,305,290,295,300,310,320]
ZonesInfo = [[[0 for _ in range(3)] for _ in range(2)] for _ in range(4)]   # 3 values , 4 zones , 2 periods
numberOfUsers = 70
numberOfPeriods = 2
usersTupples = [[[0 for _ in range(4)] for _ in range(2)] for _ in range(numberOfUsers)] # Four values (m, b , d and ID_z) , two periods and 10 users
ZonalDeviationWeight,totalDeviation = [0 for _ in range(2)], [0 for _ in range(2)]
# variables necassary for functional encryption and encoding
# 1- Number of vector's Elements ( one extra element for encoding number zero)
D = 13
# 2- Number of vectors and Number of bits representing the decmilal number to be encoded
N = D-1

# Setting users data (two periods, every two tupples belong to one user)
# To change numberOfPeriods, we need to change the way we read the data
def setUsersData():
    try:
        with open("/Users/emanahmed/Documents/GitHub/ZPPB-LEM2/data/input-P0-1.txt", 'r') as file:
            u,p,v=0,0,0
            n=0
            for line in file:
                numbers = line.split()
                for i in range(numberOfUsers*8):
                    usersTupples[u][p][v]= int(numbers[i]) # u is the user ID , p is the period number , v is the value (m, b ,d and ID_z)
                    v+=1
                    n+=1
                    if n==4: v,p=0,1
                    elif n==8:
                        v,p,n=0,0,0
                        u+=1
    except FileNotFoundError:
        print(f"The file '{file_path}' was not found.")

# Setting zones info, should get this info from MPC
def ZoneInfo():
    for i in range(0,numberOfUsers):
        for j in range(numberOfPeriods):
            ZonesInfo[usersTupples[i][j][3]][j][0]+=(usersTupples[i][j][0] - usersTupples[i][j][1])
            ZonesInfo[usersTupples[i][j][3]][j][1]+=usersTupples[i][j][2]
            ZonesInfo[usersTupples[i][j][3]][j][2]+=(1-usersTupples[i][j][2])

# Total deviation
def tdv():
    for i in range(numberOfPeriods):
        for j in range(4):#Zones
            totalDeviation[i]+=ZonesInfo[j][i][0]
    print('Total deviation',totalDeviation)

# Zonal deviationWeight
# Should get this data from MPC
def devWeight():
    for i in range(numberOfPeriods): # loop through the trading periods
        TotalOversupplyingZonesDeviations,TotalUndersupplyingZonesDeviations = 0,0
        if (totalDeviation[i] >0):
          for j in range(4):
            if (ZonesInfo[j][i][0] >0): # Check if the total deviations of the zone is positive
                TotalOversupplyingZonesDeviations+=ZonesInfo[j][i][0]
          print('Total deviation of oversupplying zones at period',i,'is: ',TotalOversupplyingZonesDeviations)
          ZonalDeviationWeight[i]= totalDeviation[i]/TotalOversupplyingZonesDeviations
        elif (totalDeviation[i] <0):
           for j in range(4):
              if (ZonesInfo[j][i][0] <0):
                 TotalUndersupplyingZonesDeviations+=ZonesInfo[j][i][0]
           print('Total deviation of undersupplying zones at period',i,'is: ',TotalUndersupplyingZonesDeviations)
           ZonalDeviationWeight[i]= totalDeviation[i]/TotalUndersupplyingZonesDeviations
        print("Zonal deviation weight for period",i,"is: ",ZonalDeviationWeight[i])

def main():
    setUsersData()
    ZoneInfo()
#    print(usersTupples)
    tdv()
    devWeight()

    # IPE keysSetup
    KAuth = KeyAuthority()
    KAuth.ipeSetup()
    supplier = Supplier()
    threads = []
    start_time = time.time()
    for u in range(numberOfUsers):
        print("USER (", u ,") BILLING DETAILS: ")
        supplier.init()
        for i in range(numberOfPeriods):
            supplier.getSMEncryptedData(u,i)
            supplier.getLEMOEncryptedData(u,i)
            thread = threading.Thread(target=supplier.ComputeBill,args=(u,i))
            threads.append(thread)
            thread.start()
#            supplier.ComputeBill(u,i) #Compute bill on encrypted data, per trading period
            supplier.computeIVCommitment(u,i) #Compute IV commitmements and add it to the previus commitmnts
    print("computation time for supplier, per trading period", time.time() - start_time)
#        supplier.getDecKey(u) #Get bill decryption key from KA
#        supplier.decryptBill(u) #Compute and decrypt indivudal bill per billing period
#        supplier.checkIVCommitments(u) # Validate IV

    # For testing
'''    print("For testing:")
    Bill =0
    supplier.getSMEncryptedData(0)
    supplier.getLEMOEncryptedData(0)
    for i in range(0,2): #2 periods
        dev = supplier.checkDeviations(i)
        Bill += usersTupples[0][i][0] * TP[i]
        if (totalDeviation[i]>0) and (ZonesInfo[usersTupples[0][i][3]][i][0] >0 )and (dev >0):
            Bill += (ZonesInfo[usersTupples[0][i][3]][i][0] * ZonalDeviationWeight[i]/ZonesInfo[usersTupples[0][i][3]][i][1]) * (FiT[i] - TP[i]) * usersTupples[0][i][2]
        elif (dev<0) * (ZonesInfo[usersTupples[0][i][3]][i][0]<0 ) * (totalDeviation[i]<0):
            Bill += (ZonesInfo[usersTupples[0][i][3]][i][0] * ZonalDeviationWeight[i]/ZonesInfo[usersTupples[0][i][3]][i][2]) * (RP[i] - TP[i]) * (1 - usersTupples[0][i][2])
    Bill = Bill % pow(2,23)
    print("Bill computation in clear (for testing) is: ", Bill)

    Bill=0
    for i in range(0,2): #2 periods
        Bill += usersTupples[0][i][0] * TP[i]
    Bill = Bill % pow(2,23)
    print("Bill computation without deviations in clear (for testing) is: ", Bill)'''

#main()
cProfile.run("main()")
