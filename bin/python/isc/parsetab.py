
# parsetab.py
# This file is automatically generated. Do not edit.
_tabversion = '3.5'

_lr_method = 'LALR'

_lr_signature = '546327755EF0D54CB8F520B87CB71232'
    
_lr_action_items = {'STR':([3,4,36,],[14,14,14,]),'STANDBY':([21,23,38,53,59,76,81,84,],[27,27,27,27,-18,-31,-19,-32,]),'ROLL_PERIOD':([21,23,38,53,59,76,81,84,],[28,28,28,28,-18,-31,-19,-32,]),'NUMBER':([40,41,60,61,62,63,73,],[70,70,77,70,79,70,70,]),'KEY_SIZE':([21,23,38,53,59,76,81,84,],[29,29,29,29,-18,-31,-19,-32,]),'NONE':([40,41,61,63,73,],[69,69,69,69,69,]),'SEMI':([12,13,14,20,22,24,26,30,32,33,34,35,39,43,44,45,46,49,50,51,52,54,55,56,57,64,65,66,67,68,69,70,71,72,74,75,77,78,79,80,82,83,],[-8,-9,-7,25,48,58,59,-25,-27,-26,-21,-29,-28,-22,-24,-23,-20,-36,-38,-39,-37,-33,76,-35,-34,-40,-49,81,-17,-48,-15,-14,-42,-41,-30,84,-47,-43,-46,-44,-16,-45,]),'PRE_PUBLISH':([21,23,38,53,59,76,81,84,],[31,31,31,31,-18,-31,-19,-32,]),'POLICY':([0,1,2,5,7,8,9,10,21,25,38,48,58,59,81,],[-3,3,3,-4,-5,-2,-6,-1,36,-13,36,-12,-11,-18,-19,]),'$end':([1,5,7,8,9,10,25,48,58,],[0,-4,-5,-2,-6,-1,-13,-12,-11,]),'RBRACE':([38,53,59,76,81,84,],[67,74,-18,-31,-19,-32,]),'ALGORITHM':([21,38,59,81,],[37,37,-18,-19,]),'DATESUFFIX':([3,4,36,70,],[13,13,13,82,]),'KEYTTL':([21,23,38,53,59,76,81,84,],[40,40,40,40,-18,-31,-19,-32,]),'COVERAGE':([21,23,38,53,59,76,81,84,],[41,41,41,41,-18,-31,-19,-32,]),'DIRECTORY':([21,38,59,81,],[42,42,-18,-19,]),'LBRACE':([11,12,13,14,15,16,17,18,19,],[-10,-8,-9,-7,-10,-10,21,21,23,]),'ZONE':([0,1,2,5,7,8,9,10,25,48,58,],[-3,4,4,-4,-5,-2,-6,-1,-13,-12,-11,]),'ALGORITHM_POLICY':([0,1,2,5,7,8,9,10,25,48,58,],[-3,6,6,-4,-5,-2,-6,-1,-13,-12,-11,]),'KEYTYPE':([3,4,27,28,29,31,36,47,],[12,12,60,61,62,63,12,73,]),'QSTRING':([42,],[72,]),'ALGNAME':([6,37,],[16,65,]),'POST_PUBLISH':([21,23,38,53,59,76,81,84,],[47,47,47,47,-18,-31,-19,-32,]),}

_lr_action = {}
for _k, _v in _lr_action_items.items():
   for _x,_y in zip(_v[0],_v[1]):
      if not _x in _lr_action:  _lr_action[_x] = {}
      _lr_action[_x][_k] = _y
del _lr_action_items

_lr_goto_items = {'policy_option':([21,38,],[26,66,]),'zone_policy':([1,2,],[7,7,]),'duration':([40,41,61,63,73,],[68,71,78,80,83,]),'postpublish_option':([21,23,38,53,],[30,49,30,49,]),'policylist':([0,],[1,]),'algorithm_option':([21,38,],[32,32,]),'keysize_option':([21,23,38,53,],[33,50,33,50,]),'directory_option':([21,38,],[34,34,]),'init':([0,],[2,]),'standby_option':([21,23,38,53,],[35,51,35,51,]),'policy':([1,2,],[8,10,]),'new_policy':([11,15,16,],[17,18,19,]),'coverage_option':([21,23,38,53,],[43,54,43,54,]),'alg_policy':([1,2,],[5,5,]),'policy_option_list':([21,],[38,]),'keyttl_option':([21,23,38,53,],[39,52,39,52,]),'alg_option_list':([23,],[53,]),'policy_option_group':([17,18,],[20,22,]),'name':([3,4,36,],[11,15,64,]),'alg_option_group':([19,],[24,]),'alg_option':([23,53,],[55,75,]),'prepublish_option':([21,23,38,53,],[44,56,44,56,]),'rollperiod_option':([21,23,38,53,],[45,57,45,57,]),'parent_option':([21,38,],[46,46,]),'named_policy':([1,2,],[9,9,]),}

_lr_goto = {}
for _k, _v in _lr_goto_items.items():
   for _x, _y in zip(_v[0], _v[1]):
       if not _x in _lr_goto: _lr_goto[_x] = {}
       _lr_goto[_x][_k] = _y
del _lr_goto_items
_lr_productions = [
  ("S' -> policylist","S'",1,None,None,None),
  ('policylist -> init policy','policylist',2,'p_policylist','policy.py',449),
  ('policylist -> policylist policy','policylist',2,'p_policylist','policy.py',450),
  ('init -> <empty>','init',0,'p_init','policy.py',454),
  ('policy -> alg_policy','policy',1,'p_policy','policy.py',458),
  ('policy -> zone_policy','policy',1,'p_policy','policy.py',459),
  ('policy -> named_policy','policy',1,'p_policy','policy.py',460),
  ('name -> STR','name',1,'p_name','policy.py',464),
  ('name -> KEYTYPE','name',1,'p_name','policy.py',465),
  ('name -> DATESUFFIX','name',1,'p_name','policy.py',466),
  ('new_policy -> <empty>','new_policy',0,'p_new_policy','policy.py',471),
  ('alg_policy -> ALGORITHM_POLICY ALGNAME new_policy alg_option_group SEMI','alg_policy',5,'p_alg_policy','policy.py',475),
  ('zone_policy -> ZONE name new_policy policy_option_group SEMI','zone_policy',5,'p_zone_policy','policy.py',482),
  ('named_policy -> POLICY name new_policy policy_option_group SEMI','named_policy',5,'p_named_policy','policy.py',489),
  ('duration -> NUMBER','duration',1,'p_duration_1','policy.py',495),
  ('duration -> NONE','duration',1,'p_duration_2','policy.py',500),
  ('duration -> NUMBER DATESUFFIX','duration',2,'p_duration_3','policy.py',505),
  ('policy_option_group -> LBRACE policy_option_list RBRACE','policy_option_group',3,'p_policy_option_group','policy.py',524),
  ('policy_option_list -> policy_option SEMI','policy_option_list',2,'p_policy_option_list','policy.py',528),
  ('policy_option_list -> policy_option_list policy_option SEMI','policy_option_list',3,'p_policy_option_list','policy.py',529),
  ('policy_option -> parent_option','policy_option',1,'p_policy_option','policy.py',533),
  ('policy_option -> directory_option','policy_option',1,'p_policy_option','policy.py',534),
  ('policy_option -> coverage_option','policy_option',1,'p_policy_option','policy.py',535),
  ('policy_option -> rollperiod_option','policy_option',1,'p_policy_option','policy.py',536),
  ('policy_option -> prepublish_option','policy_option',1,'p_policy_option','policy.py',537),
  ('policy_option -> postpublish_option','policy_option',1,'p_policy_option','policy.py',538),
  ('policy_option -> keysize_option','policy_option',1,'p_policy_option','policy.py',539),
  ('policy_option -> algorithm_option','policy_option',1,'p_policy_option','policy.py',540),
  ('policy_option -> keyttl_option','policy_option',1,'p_policy_option','policy.py',541),
  ('policy_option -> standby_option','policy_option',1,'p_policy_option','policy.py',542),
  ('alg_option_group -> LBRACE alg_option_list RBRACE','alg_option_group',3,'p_alg_option_group','policy.py',546),
  ('alg_option_list -> alg_option SEMI','alg_option_list',2,'p_alg_option_list','policy.py',550),
  ('alg_option_list -> alg_option_list alg_option SEMI','alg_option_list',3,'p_alg_option_list','policy.py',551),
  ('alg_option -> coverage_option','alg_option',1,'p_alg_option','policy.py',555),
  ('alg_option -> rollperiod_option','alg_option',1,'p_alg_option','policy.py',556),
  ('alg_option -> prepublish_option','alg_option',1,'p_alg_option','policy.py',557),
  ('alg_option -> postpublish_option','alg_option',1,'p_alg_option','policy.py',558),
  ('alg_option -> keyttl_option','alg_option',1,'p_alg_option','policy.py',559),
  ('alg_option -> keysize_option','alg_option',1,'p_alg_option','policy.py',560),
  ('alg_option -> standby_option','alg_option',1,'p_alg_option','policy.py',561),
  ('parent_option -> POLICY name','parent_option',2,'p_parent_option','policy.py',565),
  ('directory_option -> DIRECTORY QSTRING','directory_option',2,'p_directory_option','policy.py',569),
  ('coverage_option -> COVERAGE duration','coverage_option',2,'p_coverage_option','policy.py',573),
  ('rollperiod_option -> ROLL_PERIOD KEYTYPE duration','rollperiod_option',3,'p_rollperiod_option','policy.py',577),
  ('prepublish_option -> PRE_PUBLISH KEYTYPE duration','prepublish_option',3,'p_prepublish_option','policy.py',584),
  ('postpublish_option -> POST_PUBLISH KEYTYPE duration','postpublish_option',3,'p_postpublish_option','policy.py',591),
  ('keysize_option -> KEY_SIZE KEYTYPE NUMBER','keysize_option',3,'p_keysize_option','policy.py',598),
  ('standby_option -> STANDBY KEYTYPE NUMBER','standby_option',3,'p_standby_option','policy.py',605),
  ('keyttl_option -> KEYTTL duration','keyttl_option',2,'p_keyttl_option','policy.py',612),
  ('algorithm_option -> ALGORITHM ALGNAME','algorithm_option',2,'p_algorithm_option','policy.py',616),
]