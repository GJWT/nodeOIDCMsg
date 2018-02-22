var Message = require('../src/models/tokenProfiles/message');
var AccessToken = require('../src/models/tokenProfiles/accessToken');

var dict = {};
var SINGLE_REQUIRED_STRING = [String, true, null, null, false];
var SINGLE_OPTIONAL_STRING = [String, false, null, null, false];
var SINGLE_OPTIONAL_INT = [Number, false, null, null, false];
var SINGLE_REQUIRED_INT = [Number, true, null, null, false];
var OPTIONAL_LIST_OF_STRINGS = [[String], false, this.listSerializer,
                            this.listDeserializer, false];
var REQUIRED_LIST_OF_STRINGS = [[String], true, this.listSerializer,
                            this.listDeserializer, false];
var OPTIONAL_LIST_OF_SP_SEP_STRINGS = [[String], false, this.spSepListSerializer, this.spSepListDeserializer, false];
                                
var REQUIRED_LIST_OF_SP_SEP_STRINGS = [[String], true, this.spSepListSerializer, this.spSepListDeserializer, false];
    
var SINGLE_OPTIONAL_JSON = [dict, false, this.jsonSerializer, this.jsonDeserializer,
    false];

var REQUIRED = [SINGLE_REQUIRED_STRING, REQUIRED_LIST_OF_STRINGS,
REQUIRED_LIST_OF_SP_SEP_STRINGS];

var OPTIONAL_MESSAGE = [Message, false, this.msgSer, this.msgDeser, false];
var REQUIRED_MESSAGE = [Message, true, this.msgSer, this.msgDeser, false];

var OPTIONAL_LIST_OF_MESSAGES = [[Message], false, this.msgListSer, this.msgListDeser,
         false];

var SINGLE_OPTIONAL_DICT = (Object, false, this.jsonSerializer, this.jsonDeserializer, false)
         

var VTYPE = 0;
var VREQUIRED = 1;
var VSER = 2;
var VDESER = 3;
var VNULLALLOWED = 4;


/**
 * Factory method that can be used to easily instantiate a class instance
 * @param {*} msgtype  : The name of the class
 * @param {*} kwargs : Keyword arguments
 * return: An instance of the class or None if the name doesn't match any known class
 */
function factory(msgtype, kwargs){
    for (var i = 0; i < inspect.getMembers(sys.modules[_name_]).length; i++){
        if (inspect.isclass(obj) && obj instanceof Message){
            try{
                if (obj.name == msgType){
                    return obj(kwargs);
                }
            }catch(err){
                return;
            }
        }
    }
}

module.exports.SINGLE_OPTIONAL_STRING = SINGLE_OPTIONAL_STRING;
module.exports.OPTIONAL_LIST_OF_STRINGS = OPTIONAL_LIST_OF_STRINGS;
module.exports.SINGLE_OPTIONAL_DICT = SINGLE_OPTIONAL_DICT;
module.exports.SINGLE_OPTIONAL_INT = SINGLE_OPTIONAL_INT;
module.exports.SINGLE_REQUIRED_STRING = SINGLE_REQUIRED_STRING;