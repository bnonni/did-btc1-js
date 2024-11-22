export default {
  '@context'           : ['https://www.w3.org/ns/did/v1'],
  verificationMethod : [{
    id           : '#initialKey',
    type         : 'JsonWebKey',
    publicKeyJwk : {
      kty : 'EC',
      crv : 'secp256k1',
      x   : '029a182c787912e27145f6d82a062cbda960f4bb2c24ef5cd9ea4a667b5a0d101e'
    }
  }],
  authentication       : ['#initialKey'],
  assertionMethod      : ['#initialKey'],
  capabilityInvocation : ['#initialKey'],
  capabilityDelegation : ['#initialKey'],
  service              : [
    {
      id              : '#initial_p2pkh',
      type            : 'SingletonBeacon',
      serviceEndpoint : 'bitcoin:mqzVvotMQAWcxPTHUdBs1Nq7Mn7K3iZeCG'
    },
    {
      id              : '#initial_p2wpkh',
      type            : 'SingletonBeacon',
      serviceEndpoint : 'bitcoin:tb1qwtnw2v33j49jsava5ypqtcug3ndm5akavvtp43'
    },
    {
      id              : '#initial_p2tr',
      type            : 'SingletonBeacon',
      serviceEndpoint : 'bitcoin:tb1pyvh0l5s4m7w293muq2u29dzfyfhhp46y4jm9lt47876h70qndm3qztafja'
    },
    {
      id              : '#smt_aggregated',
      type            : 'SMTAggregatorBeacon',
      serviceEndpoint : 'bitcoin:tb1p8fx4cmaqt0hsrnw6kprqcjtrtrhkpjvclzwra58yz8klp4r7vv4qs3hpz5'
    },
  ]
};