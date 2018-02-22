function spSepListSerializer(vals, sformat="urlencoded", lev=0){
    sformat = sformat || "urlencoded";
    lev = lev || 0;
    if (vals instanceof String){
        return vals;
    }else{
        return " ".join(vals)
    }
};

function spSepListDeserializer(val, sformat="urlencoded"){
    if (val instanceof String){
        return val.split(" ");
    } else if ((val instanceof Array) && (val.length == 1)){
        return val[0].split(" ");
    } else {
        return val;
    }
};

function msgDeser(val, sformat){
    if (val instanceof Token){
        return val;
    }else if (["dict", "json"].indexOf(sformat)){
        if (!(val instanceof String)){
            val = json.dumps(val);
            sformat = "json";
        }
    var token = new Token();
    return token.deserialize(val, sformat)
    }
};

function msgSer(inst, sformat, lev=0){
    var formats = ["urlencoded", "json"];
    if (formats.indexOf(sformat) !== -1){
        if (inst instanceof dict){
            if (sformat == 'json'){
                res = json.dumps(inst);
            }else{
                for (var i = 0; i < Object.keys(inst).length; i++){
                    var key = Object.keys(inst)[i];
                    var val = inst[key];
                    res = urlencode([(key, val)]);
                }    
            }
        }else if (inst instanceof Token){
            res = inst.serialize(sformat, lev);
        }else{
            res = inst;
        }
    }else if (sformat == "dict"){
        if (isinstance(inst, Message)){
            res = inst.serialize(sformat, lev);
        } else if (inst instanceof dict){
            res = inst;
        } else if (inst instanceof String){
            res = inst;
        } else{
            console.log("Wrong type");
        }
    }else{
        console.log("Unknown sformat");
    }
    return res;
};

function msgListDeser(val, sformat, lev){
    lev = lev || 0;
    sformat = sformat || "urlencoded";    
    if (val instanceof dict){
        return [Token(val)];
    }

    var _res = []
    for (var i = 0; i < val.length; i++){
        _res.push(msgDeser(v, sformat));        
    }
    
    return _res;
};

function msgListSer(val, sformat, lev){
    lev = lev || 0;
    sformat = sformat || "urlencoded";
    var _res = [];
    for (var i = 0; i < val.length; i++){
        var v = val[i];
        _res.push(msgSer(v, sformat));       
    }
    return _res;
};

function json_serializer(obj, sformat="urlencoded", lev=0){
    sformat = sformat || "urlencoded";    
    return json.dumps(obj)
};

function json_deserializer(txt, sformat="urlencoded"){
    sformat = sformat || "urlencoded";        
    return json.loads(txt);
};