
# parsetab.py
# This file is automatically generated. Do not edit.
_tabversion = '3.5'

_lr_method = 'LALR'

_lr_signature = '5975EE575B9492EC21D82551870C1B84'
    
_lr_action_items = {'NONE':([39,40,59,61,70,],[67,67,67,67,67,]),'LBRACE':([11,12,13,14,15,16,17,18,19,],[-10,-8,-9,-7,-10,-10,21,21,23,]),'ALGORITHM':([21,37,57,78,],[36,36,-18,-19,]),'SEMI':([12,13,14,20,22,24,26,30,32,33,34,38,41,42,43,44,47,48,49,50,52,53,54,55,62,63,64,65,66,67,68,69,71,72,74,75,76,77,79,80,],[-8,-9,-7,25,46,56,57,-24,-26,-25,-28,-27,-21,-23,-22,-20,-35,-37,-38,-36,-32,73,-34,-33,-39,-47,78,-17,-46,-15,-14,-40,-29,81,-45,-41,-44,-42,-16,-43,]),'ZONE':([0,1,2,5,7,8,9,10,25,46,56,],[-3,4,4,-4,-5,-2,-6,-1,-13,-12,-11,]),'ALGORITHM_POLICY':([0,1,2,5,7,8,9,10,25,46,56,],[-3,6,6,-4,-5,-2,-6,-1,-13,-12,-11,]),'COVERAGE':([21,23,37,51,57,73,78,81,],[40,40,40,40,-18,-30,-19,-31,]),'KEYTYPE':([3,4,27,28,29,31,35,45,],[12,12,58,59,60,61,12,70,]),'ROLL_PERIOD':([21,23,37,51,57,73,78,81,],[28,28,28,28,-18,-30,-19,-31,]),'DATESUFFIX':([3,4,35,68,],[13,13,13,79,]),'RBRACE':([37,51,57,73,78,81,],[65,71,-18,-30,-19,-31,]),'STANDBY':([21,23,37,51,57,73,78,81,],[27,27,27,27,-18,-30,-19,-31,]),'KEY_SIZE':([21,23,37,51,57,73,78,81,],[29,29,29,29,-18,-30,-19,-31,]),'ALGNAME':([6,36,],[16,63,]),'NUMBER':([39,40,58,59,60,61,70,],[68,68,74,68,76,68,68,]),'PRE_PUBLISH':([21,23,37,51,57,73,78,81,],[31,31,31,31,-18,-30,-19,-31,]),'KEYTTL':([21,23,37,51,57,73,78,81,],[39,39,39,39,-18,-30,-19,-31,]),'STR':([3,4,35,],[14,14,14,]),'POLICY':([0,1,2,5,7,8,9,10,21,25,37,46,56,57,78,],[-3,3,3,-4,-5,-2,-6,-1,35,-13,35,-12,-11,-18,-19,]),'POST_PUBLISH':([21,23,37,51,57,73,78,81,],[45,45,45,45,-18,-30,-19,-31,]),'$end':([1,5,7,8,9,10,25,46,56,],[0,-4,-5,-2,-6,-1,-13,-12,-11,]),}

_lr_action = {}
for _k, _v in _lr_action_items.items():
   for _x,_y in zip(_v[0],_v[1]):
      if not _x in _lr_action:  _lr_action[_x] = {}
      _lr_action[_x][_k] = _y
del _lr_action_items

_lr_goto_items = {'policy_option':([21,37,],[26,64,]),'zone_policy':([1,2,],[7,7,]),'duration':([39,40,59,61,70,],[66,69,75,77,80,]),'postpublish_option':([21,23,37,51,],[30,47,30,47,]),'policylist':([0,],[1,]),'algorithm_option':([21,37,],[32,32,]),'keysize_option':([21,23,37,51,],[33,48,33,48,]),'init':([0,],[2,]),'standby_option':([21,23,37,51,],[34,49,34,49,]),'policy':([1,2,],[8,10,]),'new_policy':([11,15,16,],[17,18,19,]),'coverage_option':([21,23,37,51,],[41,52,41,52,]),'alg_policy':([1,2,],[5,5,]),'policy_option_list':([21,],[37,]),'keyttl_option':([21,23,37,51,],[38,50,38,50,]),'alg_option_list':([23,],[51,]),'policy_option_group':([17,18,],[20,22,]),'name':([3,4,35,],[11,15,62,]),'alg_option_group':([19,],[24,]),'alg_option':([23,51,],[53,72,]),'prepublish_option':([21,23,37,51,],[42,54,42,54,]),'rollperiod_option':([21,23,37,51,],[43,55,43,55,]),'parent_option':([21,37,],[44,44,]),'named_policy':([1,2,],[9,9,]),}

_lr_goto = {}
for _k, _v in _lr_goto_items.items():
   for _x, _y in zip(_v[0], _v[1]):
       if not _x in _lr_goto: _lr_goto[_x] = {}
       _lr_goto[_x][_k] = _y
del _lr_goto_items
_lr_productions = [
  ("S' -> policylist","S'",1,None,None,None),
  ('policylist -> init policy','policylist',2,'p_policylist','policy.py',358),
  ('policylist -> policylist policy','policylist',2,'p_policylist','policy.py',359),
  ('init -> <empty>','init',0,'p_init','policy.py',363),
  ('policy -> alg_policy','policy',1,'p_policy','policy.py',367),
  ('policy -> zone_policy','policy',1,'p_policy','policy.py',368),
  ('policy -> named_policy','policy',1,'p_policy','policy.py',369),
  ('name -> STR','name',1,'p_name','policy.py',373),
  ('name -> KEYTYPE','name',1,'p_name','policy.py',374),
  ('name -> DATESUFFIX','name',1,'p_name','policy.py',375),
  ('new_policy -> <empty>','new_policy',0,'p_new_policy','policy.py',380),
  ('alg_policy -> ALGORITHM_POLICY ALGNAME new_policy alg_option_group SEMI','alg_policy',5,'p_alg_policy','policy.py',384),
  ('zone_policy -> ZONE name new_policy policy_option_group SEMI','zone_policy',5,'p_zone_policy','policy.py',391),
  ('named_policy -> POLICY name new_policy policy_option_group SEMI','named_policy',5,'p_named_policy','policy.py',398),
  ('duration -> NUMBER','duration',1,'p_duration_1','policy.py',404),
  ('duration -> NONE','duration',1,'p_duration_2','policy.py',409),
  ('duration -> NUMBER DATESUFFIX','duration',2,'p_duration_3','policy.py',414),
  ('policy_option_group -> LBRACE policy_option_list RBRACE','policy_option_group',3,'p_policy_option_group','policy.py',433),
  ('policy_option_list -> policy_option SEMI','policy_option_list',2,'p_policy_option_list','policy.py',437),
  ('policy_option_list -> policy_option_list policy_option SEMI','policy_option_list',3,'p_policy_option_list','policy.py',438),
  ('policy_option -> parent_option','policy_option',1,'p_policy_option','policy.py',442),
  ('policy_option -> coverage_option','policy_option',1,'p_policy_option','policy.py',443),
  ('policy_option -> rollperiod_option','policy_option',1,'p_policy_option','policy.py',444),
  ('policy_option -> prepublish_option','policy_option',1,'p_policy_option','policy.py',445),
  ('policy_option -> postpublish_option','policy_option',1,'p_policy_option','policy.py',446),
  ('policy_option -> keysize_option','policy_option',1,'p_policy_option','policy.py',447),
  ('policy_option -> algorithm_option','policy_option',1,'p_policy_option','policy.py',448),
  ('policy_option -> keyttl_option','policy_option',1,'p_policy_option','policy.py',449),
  ('policy_option -> standby_option','policy_option',1,'p_policy_option','policy.py',450),
  ('alg_option_group -> LBRACE alg_option_list RBRACE','alg_option_group',3,'p_alg_option_group','policy.py',454),
  ('alg_option_list -> alg_option SEMI','alg_option_list',2,'p_alg_option_list','policy.py',458),
  ('alg_option_list -> alg_option_list alg_option SEMI','alg_option_list',3,'p_alg_option_list','policy.py',459),
  ('alg_option -> coverage_option','alg_option',1,'p_alg_option','policy.py',463),
  ('alg_option -> rollperiod_option','alg_option',1,'p_alg_option','policy.py',464),
  ('alg_option -> prepublish_option','alg_option',1,'p_alg_option','policy.py',465),
  ('alg_option -> postpublish_option','alg_option',1,'p_alg_option','policy.py',466),
  ('alg_option -> keyttl_option','alg_option',1,'p_alg_option','policy.py',467),
  ('alg_option -> keysize_option','alg_option',1,'p_alg_option','policy.py',468),
  ('alg_option -> standby_option','alg_option',1,'p_alg_option','policy.py',469),
  ('parent_option -> POLICY name','parent_option',2,'p_parent_option','policy.py',473),
  ('coverage_option -> COVERAGE duration','coverage_option',2,'p_coverage_option','policy.py',477),
  ('rollperiod_option -> ROLL_PERIOD KEYTYPE duration','rollperiod_option',3,'p_rollperiod_option','policy.py',481),
  ('prepublish_option -> PRE_PUBLISH KEYTYPE duration','prepublish_option',3,'p_prepublish_option','policy.py',488),
  ('postpublish_option -> POST_PUBLISH KEYTYPE duration','postpublish_option',3,'p_postpublish_option','policy.py',495),
  ('keysize_option -> KEY_SIZE KEYTYPE NUMBER','keysize_option',3,'p_keysize_option','policy.py',502),
  ('standby_option -> STANDBY KEYTYPE NUMBER','standby_option',3,'p_standby_option','policy.py',509),
  ('keyttl_option -> KEYTTL duration','keyttl_option',2,'p_keyttl_option','policy.py',516),
  ('algorithm_option -> ALGORITHM ALGNAME','algorithm_option',2,'p_algorithm_option','policy.py',520),
]
