import random
import os
import hashlib
import binascii
import sys
import encoding
from ecc import point_add, scalar_mult, curve
# Path hack
sys.path.insert(0, os.path.abspath('.'))
sys.path.insert(1, os.path.abspath('..'))
from fhipe.fhipe import ipe

# variables necassary for functional encryption and encoding
# 1- Number of Vector's Elements ( one extra element for encoding the number zero)
D = 12
# 2- Number of vectors and Number of bits representing the decmilal number to be encoded
N = D-1

class KeyAuthority:
  readingsKeys,pTypeKeys,cTypeKeys = [],[],[]
  DecKey,pTypeDecKey,cTypeDecKey,rDecKey = 0 ,0, 0, 0
  pp, sk = 0, 0
  def getReadingsEncryptionKeys(self):
    for i in range(0,2): #10 periods
      n = int.from_bytes(os.urandom(4), byteorder="big")
      KeyAuthority.readingsKeys.append(n)
    #print("Secret meter reading keys are: ",KeyAuthority.readingsKeys)
    return KeyAuthority.readingsKeys

  def getDecryptionKey(self,decPKeyHelper,decCKeyHelper):
    KeyAuthority.DecKey = self.getReadingsDecryptionKey() + self.getPTypeDecryptionKey(decPKeyHelper) + self.getCTypeDecryptionKey(decCKeyHelper)
    print("Decryption key is: ", KeyAuthority.DecKey)
    return KeyAuthority.DecKey

  def getReadingsDecryptionKey(self):
    for i in range(0,2):
      KeyAuthority.rDecKey += KeyAuthority.readingsKeys[i] * TP[i]
      KeyAuthority.rDecKey = KeyAuthority.rDecKey % pow(2,23)
    #print("Decryption key is: ", KeyAuthority.rDecKey)
    return KeyAuthority.rDecKey

  def getPTypeEncryptionKeys(self):
    for i in range(0,2): #10 periods
      n = int.from_bytes(os.urandom(4), byteorder="big")
      KeyAuthority.pTypeKeys.append(n)
    #print("Secret p type keys are: ",KeyAuthority.pTypeKeys)
    return KeyAuthority.pTypeKeys

  def getPTypeDecryptionKey(self,decPKeyHelper):
    for i in range(0,2):
      KeyAuthority.pTypeDecKey += decPKeyHelper[i] * KeyAuthority.pTypeKeys[i] * (FiT[i] - TP[i]) * vs[i]
      KeyAuthority.pTypeDecKey = KeyAuthority.pTypeDecKey % pow(2,23)
    #print("Decryption key is: ", KeyAuthority.pTypeDecKey)
    return KeyAuthority.pTypeDecKey

  def getCTypeEncryptionKeys(self):
    for i in range(0,2): #10 periods
      n = int.from_bytes(os.urandom(4), byteorder="big")
      KeyAuthority.cTypeKeys.append(n)
    #print("Secret c type keys are: ",KeyAuthority.cTypeKeys)
    return KeyAuthority.cTypeKeys

  def getCTypeDecryptionKey(self,decCKeyHelper):
    for i in range(0,2):
      KeyAuthority.cTypeDecKey += decCKeyHelper[i] * KeyAuthority.cTypeKeys[i] * (RP[i] - TP[i]) * vs[i]
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
    self.MaskedReadings,self.ComittedReadings= [0 for _ in range(2)],[0 for _ in range(2)]
#    self.EncodedReadings = [[0]*D for _ in range(N)]
    self.sky = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]

  def getMaskedReadings(self,u):
    randomKeys = self.KAuth.getReadingsEncryptionKeys()
    for i in range(0,2):
      self.MaskedReadings[i]= usersTupples[u][i][0] + randomKeys[i]
    print("Masked Readings", self.MaskedReadings)
    return self.MaskedReadings

  # Pedersen Commitment
  def getCommitedReadings(self,u):
    for i in range(0,2):
      self.ComittedReadings[i]= point_add(scalar_mult(usersTupples[u][i][0],curve.g),scalar_mult(5,curve.g))
    return self.ComittedReadings

  # InnerProducts functionl encryption (meater readings)
  def getIpfeEncryptedReading(self,u):
      for i in range(2): # 10 meter readings for each of the 10 periods
          for j in range(N): # N vectors per meter reading
              self.sky[i][j]= ipe.keygen(self.KAuth.getSecretKey(), encoding.VectorYEncoding(usersTupples[u][i][0],D)[j])
      return self.sky
      '''self.EncodedReadings = encoding.VectorYEncoding(meterReadings[0],D)
      for i in range(N):
          self.sky[i]= ipe.keygen(self.KAuth.getSecretKey(), self.EncodedReadings[i])
      print("Second",self.sky[0])
      return self.sky'''

class MarketOperator:
  def __init__(self):
      self.ComittedAmounts = [0 for _ in range(2)]
      self.KAuth = KeyAuthority()
      self.MaskedPTypes, self.MaskedCTypes = [0 for _ in range(2)],[0 for _ in range(2)]
#      self.EncodedVolumesL = self.EncodedVolumesR = [[0]*D for _ in range(N)]
      self.skxL = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
      self.skxR = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]

  # mask prosumer type vector
  def getMaskedPTypes(self,u):
    randomKeys = self.KAuth.getPTypeEncryptionKeys()
    for i in range(0,2):
      self.MaskedPTypes[i] = usersTupples[u][i][2] + randomKeys[i] #prosumers encoding: 1 for prosumer and 0 for consumer
    print("Masked prosumer vector", self.MaskedPTypes)
    return self.MaskedPTypes

  # mask consumer type vector
  def getMaskedCTypes(self,u):
    randomKeys = self.KAuth.getCTypeEncryptionKeys()
    for i in range(0,2):
      self.MaskedCTypes[i]= 1 - usersTupples[u][i][2]+ randomKeys[i] #consumers encoding: 0 for prosumer and 1 for consumer
    print("Masked consumer vector", self.MaskedCTypes)
    return self.MaskedCTypes

  def getComittedAmounts(self,u):
    for i in range(0,2):
       self.ComittedAmounts[i] = point_add(scalar_mult(-1 * usersTupples[u][i][1],curve.g),scalar_mult(7,curve.g))
    return self.ComittedAmounts

  # InnerProducts functionl encryption (trading volumes)
  def getIpfeEncryptedVolume(self,u):
      for i in range(2):
          if usersTupples[u][i][2]==1:
              for j in range(N):
                  self.skxL[i][j]= ipe.encrypt(self.KAuth.getSecretKey(), encoding.VectorXLEncoding(usersTupples[u][i][1],D)[j])
                  self.skxR[i][j]= ipe.encrypt(self.KAuth.getSecretKey(), encoding.VectorXREncoding(usersTupples[u][i][1],D)[j])
          else: # check if the user is a consumer, flip the two X vectors over to get a correct less than , greater than comparision for the negative values (as we simply have either two positve values or two negatvie values to compare)
               for j in range(N):
                   self.skxL[i][j]= ipe.encrypt(self.KAuth.getSecretKey(), encoding.VectorXREncoding(usersTupples[u][i][1],D)[j])
                   self.skxR[i][j]= ipe.encrypt(self.KAuth.getSecretKey(), encoding.VectorXLEncoding(usersTupples[u][i][1],D)[j])
      return self.skxL,self.skxR

class Supplier:
  def __init__(self):
        self.BillCT, self.maskedReadings, self.maskedPTypes, self.maskedCTypes = [0 for _ in range(numberOfUsers)],[0 for _ in range(numberOfUsers)],[0 for _ in range(numberOfUsers)],[0 for _ in range(numberOfUsers)]
        self.EncryptedReading = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
        self.EncryptedVolumeL = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
        self.EncryptedVolumeLR = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
        self.decPKeyHelper, self.decCKeyHelper= [[0 for _ in range(2)] for _ in range(numberOfUsers)],[[0 for _ in range(2)]for _ in range(numberOfUsers)]
        self.SM = SmartMeter()
        self.KAuth = KeyAuthority()
        self.MO = MarketOperator()

  def setEncryptedData(self,u):
        self.EncryptedReading = self.SM.getIpfeEncryptedReading(u)
        self.EncryptedVolumeL,self.EncryptedVolumeR = self.MO.getIpfeEncryptedVolume(u)
        self.maskedReadings, self.maskedPTypes, self.maskedCTypes =self.SM.getMaskedReadings(u), self.MO.getMaskedPTypes(u), self.MO.getMaskedCTypes(u)

  # Check if user has deviated using IPFE
  def checkDeviations(self,i,u):

      for j in range(N): # i: period number,  self.EncryptedReading[i] to retreive the encrypted reading of period i.
          #j: every meter reading is represented using N number of encdoed vectors , each is encrypted using IPFE
      # Less than comparision , check if trading volume is less than the actual meter reading (positive deviation)
          prod = ipe.decrypt(self.KAuth.getPublicParameters(), self.EncryptedReading[i][j] , self.EncryptedVolumeL[i][j], D)
          if prod==0:return 1 # indicate positive deviation
      # Greater than comparision , check if trading volume is more than the actual meter reading (negative deviation)
          prod = ipe.decrypt(self.KAuth.getPublicParameters(),self.EncryptedReading[i][j],  self.EncryptedVolumeR[i][j], D)
          if prod==0:return -1 # indicate negative deviation
      return 0 # No deviation, trading volume is equal to meater reading

  def ComputeBill(self,u):
    for i in range(0,2):
        dev = self.checkDeviations(i,u)
#   self.BillCT += ((maskedReadings[i] * TP[i]) + ((vs[i]>0) * (self.checkDeviations(i)>0) * maskedPTypes[i] * vs[i] *(FiT[i] - TP[i])) + ((vs[i]<0) * (self.checkDeviations(i)<0) * maskedCTypes[i] * vs[i] *(RP[i] - TP[i])))
        self.BillCT[u] += (self.maskedReadings[i] * TP[i])
        if (vs[i]>0) and (dev >0):
            self.decPKeyHelper[u][i]=1
            self.BillCT[u] += self.maskedPTypes[i] * vs[i] *(FiT[i] - TP[i]) # if it is a consumer, then this added value would be removed during decryption
        elif (vs[i]<0) * (dev<0):
            self.decCKeyHelper[u][i]=1
            self.BillCT[u] += self.maskedCTypes[i] * vs[i] *(RP[i] - TP[i]) # if it is a prosumer, then this added value would be removed during decryption
        self.BillCT[u] = self.BillCT[u] % pow(2,23)
    print("Encrypted bill is: ", self.BillCT[u])

  def getCorrectBills(self,u):
    DecKey = self.KAuth.getDecryptionKey(self.decPKeyHelper[u], self.decCKeyHelper[u])
    Bill = (self.BillCT[u] - DecKey) % pow(2,23)
    print("The bill after decryption is: ", Bill/1000)

  def checkIVCommitments(self,u): #Compute individual deviations commitmements and aggregate them
    ComittedReadings = self.SM.getCommitedReadings(u)
    ComittedAmounts = self.MO.getComittedAmounts(u)

    #test
    '''t = point_add(scalar_mult(usersTupples[u][0][0],curve.g),scalar_mult(5,curve.g))
    t2 = point_add(scalar_mult(-1 * usersTupples[u][0][1],curve.g),scalar_mult(7,curve.g))
    t3 = point_add(scalar_mult(usersTupples[u][1][0],curve.g),scalar_mult(5,curve.g))
    t4 = point_add(scalar_mult(-1 * usersTupples[u][1][1],curve.g),scalar_mult(7,curve.g))
    t5 = point_add(t,t2)
    t6 = point_add(t3,t4)
    total = point_add(t5,t6)
    total2 = point_add(scalar_mult(usersTupples[u][0][0] + usersTupples[u][1][0] + (-1 * usersTupples[u][0][1]) + (-1 * usersTupples[u][1][1]),curve.g),scalar_mult(7+5+7+5,curve.g))
    '''
    agg = point_add(ComittedAmounts[0],ComittedReadings[0])
    for i in range(1,2):
        Iv = point_add(ComittedAmounts[i],ComittedReadings[i])
        agg = point_add(agg,Iv)

    Result = 0
    for i in range(0,2):
        Result += (usersTupples[u][i][0] + (-1 * usersTupples[u][i][1]))
    #R = randomKeys[0] + randomKeys[0]
    agg2 = point_add(scalar_mult(Result ,curve.g),scalar_mult(24,curve.g))
    print ("\nComparsision result...")
    if (agg[0]==agg2[0]):
    	print ("Success. Individual deviations are correct.")
    else:
    	print ("Failure!")

TP = [156,201,233,160,247,210,195,262,187,143] 
FiT = [100,90,95,100,100,99,97,95,98,99]
RP = [290,300,295,285,305,290,295,300,310,320]
vs = [-45,50,37.6,-10,-23,44,-31,39,41,-18] # Deviation share for each period (total deviation (per watt)/number of prosumers or consumers)
numberOfUsers = 10
usersTupples = [[[0 for _ in range(3)] for _ in range(2)] for _ in range(numberOfUsers)] # Three values (mr, tv and type) , two periods and 10 users

# Inner-product functional encryption keysSetup
KAuth = KeyAuthority()
KAuth.ipeSetup()
supplier = Supplier()

# Setting users data (two periods, every two tupples belong to one user)
try:
    with open("/Users/emanahmed/Documents/GitHub/ZPPB-LEM2/data/input-P0-0.txt", 'r') as file:
        u,p,v=0,0,0
        n=0
        for line in file:
            numbers = line.split()
            for i in range(numberOfUsers*6):
                usersTupples[u][p][v]= int(numbers[i]) # u is the user ID , p is the period number , v is the value ( mr,tv or type)
                v+=1
                n+=1
                if n==3: v,p=0,1
                elif n==6:
                    v,p,n=0,0,0
                    u+=1

except FileNotFoundError:
    print(f"The file '{file_path}' was not found.")
print(usersTupples)
supplier.setEncryptedData(0)
supplier.ComputeBill(0) #Compute bill for user (0) , encrypted
supplier.getCorrectBills(0)
supplier.checkIVCommitments(0)

supplier.setEncryptedData(1)
supplier.ComputeBill(1) #Compute bill for user (0) , encrypted
supplier.getCorrectBills(1)
supplier.checkIVCommitments(1)

# For testing
Bill =0
for i in range(0,2): #2 periods
    Bill += usersTupples[0][i][0] * TP[i]
    if (supplier.checkDeviations(i,0)>0) * (vs[i]>0):
        Bill += vs[i] * (FiT[i] - TP[i]) * usersTupples[0][i][2]
    elif (supplier.checkDeviations(i,0)<0) * (vs[i]<0):
        Bill += vs[i] * (RP[i] - TP[i]) * (1 - usersTupples[0][i][2])
#Bill = Bill % pow(2,23)
print("Bill computation in clear (for testing) is: ", Bill/1000)

Bill=0
for i in range(0,2): #2 periods
    Bill += usersTupples[0][i][0] * TP[i]
Bill = Bill % pow(2,23)
print("Bill computation without deviations in clear (for testing) is: ", Bill/1000)
