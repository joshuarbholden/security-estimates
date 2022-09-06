from math import log
from Kyber_failure import p2_cyclotomic_error_probability
from MLWE_security import MLWE_summarize_attacks, MLWEParameterSet
from proba_util import build_mod_switching_error_law

from warnings import warn

class KyberParameterSet:
    def __init__(self, n, m, ks, ke,  q, rqk, rqc, rq2, ke_ct=None):
        if ke_ct is None:
            ke_ct = ke
        self.n = n
        self.m = m
        self.ks = ks     # binary distribution for the secret key  # s?
        self.ke = ke    # binary distribution for the ciphertext errors # ciphertext??? e and/or r?  Doesn't really matter I guess given line 24 below
        self.ke_ct = ke_ct    # binary distribution for the ciphertext errors  # e1 and e2 page 11 of specs
        self.q = q
        self.rqk = rqk  # 2^(bits in the public key)  
                        ###JBH ?????? must be per element of Zq
        self.rqc = rqc  # 2^(bits in the first ciphertext)
        self.rq2 = rq2  # 2^(bits in the second ciphertext)


def Kyber_to_MLWE(kps):
    if kps.ks != kps.ke:
        raise Exception("The security script does not handle different error parameter in secrets and errors (ks != ke) ")

    # Check whether ciphertext error variance after rounding is larger than secret key error variance
    Rc = build_mod_switching_error_law(kps.q, kps.rqc)
    var_rounding = sum([i*i*Rc[i] for i in Rc.keys()])

    if kps.ke_ct/2. + var_rounding < kps.ke/2.:
        warn("The security of the ciphertext MLWE may not be stronger than the one of the public key MLWE", stacklevel=2)    

    return MLWEParameterSet(kps.n, kps.m, kps.m + 1, kps.ks, kps.q)


def communication_costs(ps):
    """ Compute the communication cost of a parameter set
    :param ps: Parameter set (ParameterSet)
    :returns: (cost_Alice, cost_Bob) (in Bytes)
    """
    A_space = 256 + ps.n * ps.m * log(ps.rqk)/log(2)
    B_space = ps.n * ps.m * log(ps.rqc)/log(2) + ps.n * log(ps.rq2)/log(2)
    return (int(round(A_space))/8., int(round(B_space))/8.)


def summarize(ps):
    print ("params: ", ps.__dict__)
    print ("com costs: ", communication_costs(ps))
    F, f = p2_cyclotomic_error_probability(ps)
    print ("failure: %.2f = 2^%.1f"%(f, log(f + 2.**(-300))/log(2))) # a little more precision


if __name__ == "__main__":
    # Parameter sets
    ps_light = KyberParameterSet(256, 2, 3, 3, 3329, 2**12, 2**10, 2**4, ke_ct=2)
    ps_Kyber512eta2 = KyberParameterSet(256, 2, 2, 2, 3329, 2**12, 2**10, 2**4)
    ps_recommended = KyberParameterSet(256, 3, 2, 2, 3329, 2**12, 2**10, 2**4)
    ps_paranoid = KyberParameterSet(256, 4, 2, 2, 3329, 2**12, 2**11, 2**5)
    ps_alkaline41 = KyberParameterSet(4, 2, 2, 2, 41, 41 , 41, 41)
    ps_alkaline41comp32 = KyberParameterSet(4, 2, 2, 2, 41, 32 , 32, 32)
    ps_alkaline29eta2 = KyberParameterSet(4, 2, 2, 2, 29, 29 , 29, 29)  # 28% failture rate
    ps_alkaline29eta2star = KyberParameterSet(4, 2, 2, 2, 29, 29 , 29, 29, ke_ct=1)  # line 33 security warning
#    ps_alkaline29eta2scomp16 = KyberParameterSet(4, 2, 2, 2, 29, 16 , 16, 16, ke_ct=1)  # 37% failure and also line 33 security warning
    ps_alkaline29eta1 = KyberParameterSet(4, 2, 1, 1, 29, 29 , 29, 29)
    ps_alkaline23eta1 = KyberParameterSet(4, 2, 1, 1, 23, 23 , 23, 23)  # NONSTANDARD q !!!
#    ps_alkaline17eta2 = KyberParameterSet(4, 2, 2, 2, 17, 17, 17, 17) # 107% failure rate!
    ps_alkaline17eta1 = KyberParameterSet(4, 2, 1, 1, 17, 17, 17, 17)
    ps_alkaline17comp16 = KyberParameterSet(4, 2, 1, 1, 17, 16, 16, 16)
#    ps_alkaline13 = KyberParameterSet(4, 2, 1, 1, 13, 13, 13, 13) # 38% failure rate

    
    # Analyses
    
    # print ("Kyber512 (light):")
    # print ("--------------------")
    # print ("security:")
    # MLWE_summarize_attacks(Kyber_to_MLWE(ps_light))
    # summarize(ps_light)
    # print ()

    # print ("Kyber768 (recommended):")
    # print ("--------------------")
    # print ("security:")
    # MLWE_summarize_attacks(Kyber_to_MLWE(ps_recommended))
    # summarize(ps_recommended)
    # print ()

    # print ("Kyber1024 (paranoid):")
    # print ("--------------------")
    # print ("security:")
    # MLWE_summarize_attacks(Kyber_to_MLWE(ps_paranoid))
    # summarize(ps_paranoid)
    # print ()

#     print ("Kyber512 eta2 (light):")
#     print ("--------------------")
#     print ("security:")
#     MLWE_summarize_attacks(Kyber_to_MLWE(ps_Kyber512eta2))
#     summarize(ps_Kyber512eta2)
#     print ()
    
    print ("Alkaline D")
    print ("--------------------")
    print ("security:")
    MLWE_summarize_attacks(Kyber_to_MLWE(ps_alkaline41))
    summarize(ps_alkaline41)
    print ()
    
    # print ("Alkaline41comp32")
    # print ("--------------------")
    # print ("security:")
    # MLWE_summarize_attacks(Kyber_to_MLWE(ps_alkaline41comp32))
    # summarize(ps_alkaline41comp32)
    # print ()
    
    print ("Alkaline C")
    print ("--------------------")
    print ("security:")
    MLWE_summarize_attacks(Kyber_to_MLWE(ps_alkaline29eta1))
    summarize(ps_alkaline29eta1)
    print ()
    
    # print ("Alkaline29eta2")
    # print ("--------------------")
    # print ("security:")
    # MLWE_summarize_attacks(Kyber_to_MLWE(ps_alkaline29eta2))
    # summarize(ps_alkaline29eta2)
    # print ()

#     print ("Alkaline29eta2scomp16")
#     print ("--------------------")
#     print ("security:")
#     MLWE_summarize_attacks(Kyber_to_MLWE(ps_alkaline29eta2scomp16))
#     summarize(ps_alkaline29eta2scomp16)
#     print ()
    
    print ("Alkaline29eta2star")
    print ("--------------------")
    print ("security:")
    MLWE_summarize_attacks(Kyber_to_MLWE(ps_alkaline29eta2star))
    summarize(ps_alkaline29eta2star)
    print ()
    
    
    print ("Alkaline AAA")
    print ("--------------------")
    print ("security:")
    MLWE_summarize_attacks(Kyber_to_MLWE(ps_alkaline23eta1))
    summarize(ps_alkaline23eta1)
    print ()
    
    
    # print ("Alkaline17comp16")
    # print ("--------------------")
    # print ("security:")
    # MLWE_summarize_attacks(Kyber_to_MLWE(ps_alkaline17comp16))
    # summarize(ps_alkaline17comp16)
    # print ()

    print ("Alkaline AAAA")
    print ("--------------------")
    print ("security:")
    MLWE_summarize_attacks(Kyber_to_MLWE(ps_alkaline17eta1))
    summarize(ps_alkaline17eta1)
    print ()

    
    # print ("Alkaline13")
    # print ("--------------------")
    # print ("security:")
    # MLWE_summarize_attacks(Kyber_to_MLWE(ps_alkaline13))
    # summarize(ps_alkaline13)
    # print ()