#include <string>
#include <string_view>
#include <set>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdlib>

#include "handler/settings.h"
#include "utils/logger.h"
#include "utils/network.h"
#include "utils/regexp.h"
#include "utils/string.h"
#include "utils/rapidjson_extra.h"
#include "subexport.h"

/// rule type lists
#define basic_types "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "SRC-IP-CIDR", "GEOIP", "MATCH", "FINAL"
// 新增meta路由规则
//string_array ClashRuleTypes = {basic_types, "IP-CIDR6", "SRC-PORT", "DST-PORT", "PROCESS-NAME"};
string_array ClashRuleTypes = {basic_types, "IP-CIDR6", "SRC-PORT", "DST-PORT", "PROCESS-NAME", "DOMAIN-REGEX", "GEOSITE", "IP-SUFFIX", "IP-ASN", "SRC-GEOIP", "SRC-IP-ASN", "SRC-IP-SUFFIX", "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME", "PROCESS-PATH-REGEX", "PROCESS-PATH", "PROCESS-NAME-REGEX", "UID", "NETWORK", "DSCP", "SUB-RULE", "RULE-SET", "AND", "OR", "NOT"};
string_array Surge2RuleTypes = {basic_types, "IP-CIDR6", "USER-AGENT", "URL-REGEX", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"};
string_array SurgeRuleTypes = {basic_types, "IP-CIDR6", "USER-AGENT", "URL-REGEX", "AND", "OR", "NOT", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"};
string_array QuanXRuleTypes = {basic_types, "USER-AGENT", "HOST", "HOST-SUFFIX", "HOST-KEYWORD"};
string_array SurfRuleTypes = {basic_types, "IP-CIDR6", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"};
string_array SingBoxRuleTypes = {basic_types, "IP-VERSION", "INBOUND", "PROTOCOL", "NETWORK", "GEOSITE", "SRC-GEOIP", "DOMAIN-REGEX", "PROCESS-NAME", "PROCESS-PATH", "PACKAGE-NAME", "PORT", "PORT-RANGE", "SRC-PORT", "SRC-PORT-RANGE", "USER", "USER-ID"};

std::string convertRuleset(const std::string &content, int type)
{
    /// Target: Surge type,pattern[,flag]
    /// Source: QuanX type,pattern[,group]
    ///         Clash payload:\n  - 'ipcidr/domain/classic(Surge-like)'

    std::string output, strLine;

    if(type == RULESET_SURGE)
        return content;

    if(regFind(content, "^payload:\\r?\\n")) /// Clash
    {
        output = regReplace(regReplace(content, "payload:\\r?\\n", "", true), R"(\s?^\s*-\s+('|"?)(.*)\1$)", "\n$2", true);
        if(type == RULESET_CLASH_CLASSICAL) /// classical type
            return output;
        std::stringstream ss;
        ss << output;
        char delimiter = getLineBreak(output);
        output.clear();
        string_size pos, lineSize;
        while(getline(ss, strLine, delimiter))
        {
            strLine = trim(strLine);
            lineSize = strLine.size();
            if(lineSize && strLine[lineSize - 1] == '\r') //remove line break
                strLine.erase(--lineSize);

            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }

            if(!strLine.empty() && (strLine[0] != ';' && strLine[0] != '#' && !(lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')))
            {
                pos = strLine.find('/');
                if(pos != std::string::npos) /// ipcidr
                {
                    if(isIPv4(strLine.substr(0, pos)))
                        output += "IP-CIDR,";
                    else
                        output += "IP-CIDR6,";
                }
                else
                {
                    if(strLine[0] == '.' || (lineSize >= 2 && strLine[0] == '+' && strLine[1] == '.')) /// suffix
                    {
                        bool keyword_flag = false;
                        while(endsWith(strLine, ".*"))
                        {
                            keyword_flag = true;
                            strLine.erase(strLine.size() - 2);
                        }
                        output += "DOMAIN-";
                        if(keyword_flag)
                            output += "KEYWORD,";
                        else
                            output += "SUFFIX,";
                        strLine.erase(0, 2 - (strLine[0] == '.'));
                    }
                    else
                        output += "DOMAIN,";
                }
            }
            output += strLine;
            output += '\n';
        }
        return output;
    }
    else /// QuanX
    {
        output = regReplace(regReplace(content, "^(?i:host)", "DOMAIN", true), "^(?i:ip6-cidr)", "IP-CIDR6", true); //translate type
        output = regReplace(output, "^((?i:DOMAIN(?:-(?:SUFFIX|KEYWORD))?|IP-CIDR6?|USER-AGENT),)\\s*?(\\S*?)(?:,(?!no-resolve).*?)(,no-resolve)?$", "\\U$1\\E$2${3:-}", true); //remove group
        return output;
    }
}

static std::string transformRuleToCommon(string_view_array &temp, const std::string &input, const std::string &group, bool no_resolve_only = false)
{
    temp.clear();
    std::string strLine;
    split(temp, input, ',');
    if(temp.size() < 2)
    {
        strLine = temp[0];
        strLine += ",";
        strLine += group;
    }
    else
    {
        strLine = temp[0];
        strLine += ",";
        strLine += temp[1];
        strLine += ",";
        strLine += group;
        if(temp.size() > 2 && (!no_resolve_only || temp[2] == "no-resolve"))
        {
            strLine += ",";
            strLine += temp[2];
        }
    }
    return strLine;
}

void rulesetToClash(YAML::Node &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, bool new_field_name)
{
    string_array allRules;
    std::string rule_group, retrieved_rules, strLine;
    std::stringstream strStrm;
    const std::string field_name = new_field_name ? "rules" : "Rule";
    YAML::Node rules;
    size_t total_rules = 0;

    if(!overwrite_original_rules && base_rule[field_name].IsDefined())
        rules = base_rule[field_name];

    std::vector<std::string_view> temp(4);
    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        retrieved_rules = x.rule_content.get();
        if(retrieved_rules.empty())
        {
            writeLog(0, "Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!", LOG_LEVEL_WARNING);
            continue;
        }
        if(startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            if(startsWith(strLine, "FINAL"))
                strLine.replace(0, 5, "MATCH");
            strLine = transformRuleToCommon(temp, strLine, rule_group);
            allRules.emplace_back(strLine);
            total_rules++;
            continue;
        }
        retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
        char delimiter = getLineBreak(retrieved_rules);

        strStrm.clear();
        strStrm<<retrieved_rules;
        std::string::size_type lineSize;
        while(getline(strStrm, strLine, delimiter))
        {
            if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                break;
            strLine = trimWhitespace(strLine, true, true); //remove whitespaces
            lineSize = strLine.size();
            if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                continue;
            if(std::none_of(ClashRuleTypes.begin(), ClashRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                continue;
            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }
            strLine = transformRuleToCommon(temp, strLine, rule_group);
            allRules.emplace_back(strLine);
        }
    }

    for(std::string &x : allRules)
    {
        rules.push_back(x);
    }

    base_rule[field_name] = rules;
}

std::string rulesetToClashStr(YAML::Node &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, bool new_field_name)
{
    std::string rule_group, retrieved_rules, strLine;
    std::stringstream strStrm;
    const std::string field_name = new_field_name ? "rules" : "Rule";
    std::string output_content = "\n" + field_name + ":\n";
    size_t total_rules = 0;

    if(!overwrite_original_rules && base_rule[field_name].IsDefined())
    {
        for(size_t i = 0; i < base_rule[field_name].size(); i++)
            output_content += "  - " + safe_as<std::string>(base_rule[field_name][i]) + "\n";
    }
    base_rule.remove(field_name);

    string_view_array temp(4);
    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        retrieved_rules = x.rule_content.get();
        if(retrieved_rules.empty())
        {
            writeLog(0, "Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!", LOG_LEVEL_WARNING);
            continue;
        }
        if(startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            if(startsWith(strLine, "FINAL"))
                strLine.replace(0, 5, "MATCH");
            strLine = transformRuleToCommon(temp, strLine, rule_group);
            output_content += "  - " + strLine + "\n";
            total_rules++;
            continue;
        }
        retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
        char delimiter = getLineBreak(retrieved_rules);

        strStrm.clear();
        strStrm<<retrieved_rules;
        std::string::size_type lineSize;
        while(getline(strStrm, strLine, delimiter))
        {
            if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                break;
            strLine = trimWhitespace(strLine, true, true); //remove whitespaces
            lineSize = strLine.size();
            if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                continue;
            if(std::none_of(ClashRuleTypes.begin(), ClashRuleTypes.end(), [strLine](const std::string& type){ return startsWith(strLine, type); }))
                continue;
            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }

            //AND & OR & NOT
            if(startsWith(strLine, "AND") || startsWith(strLine, "OR") || startsWith(strLine, "NOT"))
            {
                output_content += "  - " + strLine + "," + rule_group + "\n";
            }
            //SUB-RULE & RULE-SET
            else if (startsWith(strLine, "SUB-RULE") || startsWith(strLine, "RULE-SET"))
            {
                output_content += "  - " + strLine + "\n";
            }
            else
            //OTHER
            {
                strLine = transformRuleToCommon(temp, strLine, rule_group);
                output_content += "  - " + strLine + "\n";
            }

            //strLine = transformRuleToCommon(temp, strLine, rule_group);
            //output_content += "  - " + strLine + "\n";
            total_rules++;
        }
    }
    return output_content;
}

void rulesetToSurge(INIReader &base_rule, std::vector<RulesetContent> &ruleset_content_array, int surge_ver, bool overwrite_original_rules, const std::string &remote_path_prefix)
{
    string_array allRules;
    std::string rule_group, rule_path, rule_path_typed, retrieved_rules, strLine;
    std::stringstream strStrm;
    size_t total_rules = 0;

    switch(surge_ver) //other version: -3 for Surfboard, -4 for Loon
    {
    case 0:
        base_rule.set_current_section("RoutingRule"); //Mellow
        break;
    case -1:
        base_rule.set_current_section("filter_local"); //Quantumult X
        break;
    case -2:
        base_rule.set_current_section("TCP"); //Quantumult
        break;
    default:
        base_rule.set_current_section("Rule");
    }

    if(overwrite_original_rules)
    {
        base_rule.erase_section();
        switch(surge_ver)
        {
        case -1:
            base_rule.erase_section("filter_remote");
            break;
        case -4:
            base_rule.erase_section("Remote Rule");
            break;
        default:
            break;
        }
    }

    const std::string rule_match_regex = "^(.*?,.*?)(,.*)(,.*)$";

    string_view_array temp(4);
    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        rule_path = x.rule_path;
        rule_path_typed = x.rule_path_typed;
        if(rule_path.empty())
        {
            strLine = x.rule_content.get().substr(2);
            if(strLine == "MATCH")
                strLine = "FINAL";
            if(surge_ver == -1 || surge_ver == -2)
            {
                strLine = transformRuleToCommon(temp, strLine, rule_group, true);
            }
            else
            {
                if(!startsWith(strLine, "AND") && !startsWith(strLine, "OR") && !startsWith(strLine, "NOT"))
                    strLine = transformRuleToCommon(temp, strLine, rule_group);
            }
            strLine = replaceAllDistinct(strLine, ",,", ",");
            allRules.emplace_back(strLine);
            total_rules++;
            continue;
        }
        else
        {
            if(surge_ver == -1 && x.rule_type == RULESET_QUANX && isLink(rule_path))
            {
                strLine = rule_path + ", tag=" + rule_group + ", force-policy=" + rule_group + ", enabled=true";
                base_rule.set("filter_remote", "{NONAME}", strLine);
                continue;
            }
            if(fileExist(rule_path))
            {
                if(surge_ver > 2 && !remote_path_prefix.empty())
                {
                    strLine = "RULE-SET," + remote_path_prefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rule_path_typed) + "," + rule_group;
                    if(x.update_interval)
                        strLine += ",update-interval=" + std::to_string(x.update_interval);
                    allRules.emplace_back(strLine);
                    continue;
                }
                else if(surge_ver == -1 && !remote_path_prefix.empty())
                {
                    strLine = remote_path_prefix + "/getruleset?type=2&url=" + urlSafeBase64Encode(rule_path_typed) + "&group=" + urlSafeBase64Encode(rule_group);
                    strLine += ", tag=" + rule_group + ", enabled=true";
                    base_rule.set("filter_remote", "{NONAME}", strLine);
                    continue;
                }
                else if(surge_ver == -4 && !remote_path_prefix.empty())
                {
                    strLine = remote_path_prefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rule_path_typed) + "," + rule_group;
                    base_rule.set("Remote Rule", "{NONAME}", strLine);
                    continue;
                }
            }
            else if(isLink(rule_path))
            {
                if(surge_ver > 2)
                {
                    if(x.rule_type != RULESET_SURGE)
                    {
                        if(!remote_path_prefix.empty())
                            strLine = "RULE-SET," + remote_path_prefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rule_path_typed) + "," + rule_group;
                        else
                            continue;
                    }
                    else
                        strLine = "RULE-SET," + rule_path + "," + rule_group;

                    if(x.update_interval)
                        strLine += ",update-interval=" + std::to_string(x.update_interval);

                    allRules.emplace_back(strLine);
                    continue;
                }
                else if(surge_ver == -1 && !remote_path_prefix.empty())
                {
                    strLine = remote_path_prefix + "/getruleset?type=2&url=" + urlSafeBase64Encode(rule_path_typed) + "&group=" + urlSafeBase64Encode(rule_group);
                    strLine += ", tag=" + rule_group + ", enabled=true";
                    base_rule.set("filter_remote", "{NONAME}", strLine);
                    continue;
                }
                else if(surge_ver == -4)
                {
                    strLine = rule_path + "," + rule_group;
                    base_rule.set("Remote Rule", "{NONAME}", strLine);
                    continue;
                }
            }
            else
                continue;
            retrieved_rules = x.rule_content.get();
            if(retrieved_rules.empty())
            {
                writeLog(0, "Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!", LOG_LEVEL_WARNING);
                continue;
            }

            retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
            char delimiter = getLineBreak(retrieved_rules);

            strStrm.clear();
            strStrm<<retrieved_rules;
            std::string::size_type lineSize;
            while(getline(strStrm, strLine, delimiter))
            {
                if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                    break;
                strLine = trimWhitespace(strLine, true, true);
                lineSize = strLine.size();
                if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                    continue;

                /// remove unsupported types
                switch(surge_ver)
                {
                case -2:
                    if(startsWith(strLine, "IP-CIDR6"))
                        continue;
                    [[fallthrough]];
                case -1:
                    if(!std::any_of(QuanXRuleTypes.begin(), QuanXRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                        continue;
                    break;
                case -3:
                    if(!std::any_of(SurfRuleTypes.begin(), SurfRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                        continue;
                    break;
                default:
                    if(surge_ver > 2)
                    {
                        if(!std::any_of(SurgeRuleTypes.begin(), SurgeRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                            continue;
                    }
                    else
                    {
                        if(!std::any_of(Surge2RuleTypes.begin(), Surge2RuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                            continue;
                    }
                }

                if(strFind(strLine, "//"))
                {
                    strLine.erase(strLine.find("//"));
                    strLine = trimWhitespace(strLine);
                }

                if(surge_ver == -1 || surge_ver == -2)
                {
                    if(startsWith(strLine, "IP-CIDR6"))
                        strLine.replace(0, 8, "IP6-CIDR");
                    strLine = transformRuleToCommon(temp, strLine, rule_group, true);
                }
                else
                {
                    if(!startsWith(strLine, "AND") && !startsWith(strLine, "OR") && !startsWith(strLine, "NOT"))
                        strLine = transformRuleToCommon(temp, strLine, rule_group);
                }
                allRules.emplace_back(strLine);
                total_rules++;
            }
        }
    }

    for(std::string &x : allRules)
    {
        base_rule.set("{NONAME}", x);
    }
}

namespace
{
struct SingBoxClashRule
{
    enum class Kind
    {
        Invalid,
        Final,
        Field,
        Geo
    };

    Kind kind = Kind::Invalid;
    std::string field;
    std::string value;
    std::string geo;
    bool numeric = false;
    bool scalar = false;
};

static bool isSingBoxRejectGroup(const std::string &group, const std::set<std::string> &reject_groups)
{
    return group == "REJECT" || group == "Reject" || reject_groups.find(group) != reject_groups.end();
}

static bool parseSingBoxInt(const std::string &value, int &result)
{
    if (value.empty())
        return false;

    char *end = nullptr;
    errno = 0;
    const long parsed = std::strtol(value.c_str(), &end, 10);
    if (errno != 0 || end == value.c_str() || *end != '\0' || parsed < INT_MIN || parsed > INT_MAX)
        return false;

    result = static_cast<int>(parsed);
    return true;
}

static SingBoxClashRule parseSingBoxClashRule(const std::string &line)
{
    SingBoxClashRule result;
    std::vector<std::string_view> args;
    split(args, line, ',');
    if (args.size() < 2)
        return result;

    const std::string type = toUpper(trim(std::string(args[0])));
    const std::string value = trim(std::string(args[1]));
    if (value.empty())
        return result;

    if (type == "MATCH" || type == "FINAL")
    {
        result.kind = SingBoxClashRule::Kind::Final;
        result.value = value;
        return result;
    }

    if (type == "GEOIP" || type == "SRC-GEOIP" || type == "GEOSITE")
    {
        result.kind = SingBoxClashRule::Kind::Geo;
        result.geo = toLower(type);
        result.value = value;
        return result;
    }

    auto set_field = [&](const char *field, bool numeric = false, bool scalar = false)
    {
        result.kind = SingBoxClashRule::Kind::Field;
        result.field = field;
        result.value = value;
        result.numeric = numeric;
        result.scalar = scalar;
    };

    if (type == "DOMAIN")
        set_field("domain");
    else if (type == "DOMAIN-SUFFIX")
        set_field("domain_suffix");
    else if (type == "DOMAIN-KEYWORD")
        set_field("domain_keyword");
    else if (type == "DOMAIN-REGEX")
        set_field("domain_regex");
    else if (type == "IP-CIDR" || type == "IP-CIDR6")
        set_field("ip_cidr");
    else if (type == "SRC-IP-CIDR" || type == "SRC-IP-CIDR6" || type == "SRC-IP")
        set_field("source_ip_cidr");
    else if (type == "DST-PORT" || type == "PORT")
        set_field("port", true);
    else if (type == "SRC-PORT")
        set_field("source_port", true);
    else if (type == "PORT-RANGE")
        set_field("port_range");
    else if (type == "SRC-PORT-RANGE")
        set_field("source_port_range");
    else if (type == "PROCESS-NAME")
        set_field("process_name");
    else if (type == "PROCESS-PATH")
        set_field("process_path");
    else if (type == "PROCESS-PATH-REGEX")
        set_field("process_path_regex");
    else if (type == "PACKAGE-NAME")
        set_field("package_name");
    else if (type == "PACKAGE-NAME-REGEX")
        set_field("package_name_regex");
    else if (type == "INBOUND")
        set_field("inbound");
    else if (type == "PROTOCOL")
        set_field("protocol");
    else if (type == "NETWORK")
        set_field("network");
    else if (type == "IP-VERSION")
    {
        if (value == "4" || value == "6")
            set_field("ip_version", true, true);
    }
    else if (type == "USER")
        set_field("user");
    else if (type == "USER-ID" || type == "UID")
        set_field("user_id", true);

    if (result.kind == SingBoxClashRule::Kind::Field && result.field == "port_range")
    {
        result.value = replaceAllDistinct(result.value, "-", ":");
    }
    else if (result.kind == SingBoxClashRule::Kind::Field && result.field == "source_port_range")
    {
        result.value = replaceAllDistinct(result.value, "-", ":");
    }

    return result;
}

static bool isSafeSingBoxRuleSetCode(const std::string &code)
{
    if (code.empty())
        return false;

    for (const unsigned char c : code)
    {
        if (!std::isalnum(c) && c != '-' && c != '_' && c != '.' && c != '@' && c != '!')
            return false;
    }
    return true;
}

static void ensureSingBoxRouteObject(rapidjson::Document &doc, rapidjson::MemoryPoolAllocator<> &allocator)
{
    if (!doc.HasMember("route"))
    {
        doc.AddMember("route", rapidjson::Value(rapidjson::kObjectType), allocator);
        return;
    }

    if (!doc["route"].IsObject())
        doc["route"].SetObject();
}

static void ensureSingBoxRuleSet(rapidjson::Document &doc, const std::string &tag,
                                 rapidjson::MemoryPoolAllocator<> &allocator)
{
    ensureSingBoxRouteObject(doc, allocator);
    rapidjson::Value &route = doc["route"];

    if (!route.HasMember("rule_set"))
        route.AddMember("rule_set", rapidjson::Value(rapidjson::kArrayType), allocator);
    else if (!route["rule_set"].IsArray())
        route["rule_set"].SetArray();

    rapidjson::Value &sets = route["rule_set"];
    for (rapidjson::SizeType i = 0; i < sets.Size(); ++i)
    {
        if (sets[i].IsObject() && sets[i].HasMember("tag") && sets[i]["tag"].IsString() &&
            std::string(sets[i]["tag"].GetString()) == tag)
            return;
    }

    std::string url;
    if (startsWith(tag, "geoip-"))
        url = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/" + tag + ".srs";
    else if (startsWith(tag, "geosite-"))
        url = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/" + tag + ".srs";
    else
    {
        writeLog(0, "Unsupported sing-box rule-set tag: " + tag, LOG_LEVEL_WARNING);
        return;
    }

    rapidjson::Value item(rapidjson::kObjectType);
    item.AddMember("type", "remote", allocator);
    item.AddMember("tag", rapidjson::Value(tag.c_str(), allocator), allocator);
    item.AddMember("format", "binary", allocator);
    item.AddMember("url", rapidjson::Value(url.c_str(), allocator), allocator);

    rapidjson::Value http_client(rapidjson::kObjectType);
    http_client.AddMember("detour", "DIRECT", allocator);
    item.AddMember("http_client", http_client, allocator);

    sets.PushBack(item, allocator);
}

static void addSingBoxRuleAction(rapidjson::Value &rule, const std::string &group, bool reject,
                                 rapidjson::MemoryPoolAllocator<> &allocator)
{
    if (reject)
    {
        rule.AddMember("action", "reject", allocator);
        rule.AddMember("method", "drop", allocator);
        return;
    }

    rule.AddMember("action", "route", allocator);
    rule.AddMember("outbound",
                   rapidjson::Value(group.empty() ? "DIRECT" : group.c_str(), allocator), allocator);
}

static bool appendSingBoxGeoRule(rapidjson::Document &doc, rapidjson::Value &rules,
                                 const std::string &geo_type, const std::string &raw_value,
                                 const std::string &group, bool reject,
                                 rapidjson::MemoryPoolAllocator<> &allocator)
{
    std::string value = toLower(trim(raw_value));
    bool invert = false;
    if (!value.empty() && value[0] == '!')
    {
        invert = true;
        value.erase(0, 1);
    }

    if (value.empty())
        return false;

    const bool source = geo_type == "src-geoip";
    rapidjson::Value rule(rapidjson::kObjectType);

    if (geo_type == "geosite")
    {
        if (!isSafeSingBoxRuleSetCode(value))
            return false;

        const std::string tag = "geosite-" + value;
        ensureSingBoxRuleSet(doc, tag, allocator);
        rapidjson::Value rule_sets(rapidjson::kArrayType);
        rule_sets.PushBack(rapidjson::Value(tag.c_str(), allocator), allocator);
        rule.AddMember("rule_set", rule_sets, allocator);
    }
    else
    {
        if (value == "lan" || value == "private")
        {
            rule.AddMember(rapidjson::StringRef(source ? "source_ip_is_private" : "ip_is_private"),
                           rapidjson::Value(true), allocator);
        }
        else
        {
            if (!isSafeSingBoxRuleSetCode(value))
                return false;

            const std::string tag = "geoip-" + value;
            ensureSingBoxRuleSet(doc, tag, allocator);
            rapidjson::Value rule_sets(rapidjson::kArrayType);
            rule_sets.PushBack(rapidjson::Value(tag.c_str(), allocator), allocator);
            rule.AddMember("rule_set", rule_sets, allocator);
            if (source)
                rule.AddMember("rule_set_ip_cidr_match_source", true, allocator);
        }
    }

    if (invert)
        rule.AddMember("invert", true, allocator);

    addSingBoxRuleAction(rule, group, reject, allocator);
    rules.PushBack(rule, allocator);
    return true;
}

static bool appendSingBoxFieldRule(rapidjson::Value &rules, const SingBoxClashRule &parsed,
                                   const std::string &group, bool reject,
                                   rapidjson::MemoryPoolAllocator<> &allocator)
{
    rapidjson::Value rule(rapidjson::kObjectType);

    if (parsed.numeric)
    {
        int number = 0;
        if (!parseSingBoxInt(parsed.value, number))
            return false;
        rule.AddMember(rapidjson::Value(parsed.field.c_str(), allocator), rapidjson::Value(number),
                       allocator);
    }
    else
    {
        rule.AddMember(rapidjson::Value(parsed.field.c_str(), allocator),
                       rapidjson::Value(parsed.value.c_str(), parsed.value.size(), allocator), allocator);
    }

    addSingBoxRuleAction(rule, group, reject, allocator);
    rules.PushBack(rule, allocator);
    return true;
}

static void ensureSingBoxSystemRules(rapidjson::Value &rules,
                                     rapidjson::MemoryPoolAllocator<> &allocator)
{
    bool has_sniff = false;
    bool has_hijack_dns = false;

    if (rules.IsArray())
    {
        for (rapidjson::SizeType i = 0; i < rules.Size(); ++i)
        {
            if (!rules[i].IsObject() || !rules[i].HasMember("action") || !rules[i]["action"].IsString())
                continue;

            const std::string action = rules[i]["action"].GetString();
            if (action == "sniff")
                has_sniff = true;
            else if (action == "hijack-dns")
                has_hijack_dns = true;
        }
    }
    else
    {
        rules.SetArray();
    }

    if (has_sniff && has_hijack_dns)
        return;

    rapidjson::Value result(rapidjson::kArrayType);
    if (!has_sniff)
        result.PushBack(buildObject(allocator, "action", "sniff"), allocator);
    if (!has_hijack_dns)
        result.PushBack(buildObject(allocator, "protocol", "dns", "action", "hijack-dns"), allocator);

    for (rapidjson::SizeType i = 0; i < rules.Size(); ++i)
        result.PushBack(rules[i], allocator);

    rules.Swap(result);
}

static void setSingBoxDefaultDomainResolver(rapidjson::Document &doc,
                                            rapidjson::MemoryPoolAllocator<> &allocator)
{
    ensureSingBoxRouteObject(doc, allocator);
    rapidjson::Value &route = doc["route"];
    if (route.HasMember("default_domain_resolver"))
        return;

    bool found = false;
    if (doc.HasMember("dns") && doc["dns"].IsObject() && doc["dns"].HasMember("servers") &&
        doc["dns"]["servers"].IsArray())
    {
        const rapidjson::Value &servers = doc["dns"]["servers"];
        for (rapidjson::SizeType i = 0; i < servers.Size(); ++i)
        {
            if (!servers[i].IsObject() || !servers[i].HasMember("tag") || !servers[i]["tag"].IsString())
                continue;
            if (std::string(servers[i]["tag"].GetString()) == "dns_resolver")
            {
                found = true;
                break;
            }
        }
    }

    if (found)
        route.AddMember("default_domain_resolver", "dns_resolver", allocator);
}
} // namespace

void rulesetToSingBox(rapidjson::Document &base_rule, std::vector<RulesetContent> &ruleset_content_array,
                      bool overwrite_original_rules, const std::set<std::string> &reject_groups)
{
    using namespace rapidjson_ext;
    std::string rule_group, retrieved_rules, strLine, final;
    std::stringstream strStrm;
    size_t total_rules = 0;
    auto &allocator = base_rule.GetAllocator();

    rapidjson::Value rules(rapidjson::kArrayType);
    if (!overwrite_original_rules)
    {
        if (base_rule.HasMember("route") && base_rule["route"].IsObject() &&
            base_rule["route"].HasMember("rules") && base_rule["route"]["rules"].IsArray())
            rules.Swap(base_rule["route"]["rules"]);
    }

    if (global.singBoxAddClashModes)
    {
        rules.PushBack(buildObject(allocator, "clash_mode", "Global", "action", "route", "outbound", "GLOBAL"),
                       allocator);
        rules.PushBack(buildObject(allocator, "clash_mode", "Direct", "action", "route", "outbound", "DIRECT"),
                       allocator);
    }

    for (RulesetContent &x : ruleset_content_array)
    {
        if (global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;

        rule_group = x.rule_group;
        retrieved_rules = x.rule_content.get();
        if (retrieved_rules.empty())
        {
            writeLog(0, "Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!", LOG_LEVEL_WARNING);
            continue;
        }

        const bool reject = isSingBoxRejectGroup(rule_group, reject_groups);

        if (startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            if (startsWith(strLine, "FINAL") || startsWith(strLine, "MATCH"))
            {
                final = rule_group;
                continue;
            }
            const SingBoxClashRule parsed = parseSingBoxClashRule(strLine);
            if (parsed.kind == SingBoxClashRule::Kind::Final)
            {
                final = rule_group;
                continue;
            }
            if (parsed.kind == SingBoxClashRule::Kind::Geo)
            {
                if (appendSingBoxGeoRule(base_rule, rules, parsed.geo, parsed.value, rule_group, reject,
                                         allocator))
                    total_rules++;
                continue;
            }
            if (parsed.kind == SingBoxClashRule::Kind::Field)
            {
                if (appendSingBoxFieldRule(rules, parsed, rule_group, reject, allocator))
                    total_rules++;
                continue;
            }
            continue;
        }

        retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
        const char delimiter = getLineBreak(retrieved_rules);

        strStrm.clear();
        strStrm << retrieved_rules;

        rapidjson::Value pending(rapidjson::kObjectType);
        std::string pending_field;

        auto flush_pending = [&]()
        {
            if (pending.ObjectEmpty())
                return;

            addSingBoxRuleAction(pending, rule_group, reject, allocator);
            rules.PushBack(pending, allocator);
            pending = rapidjson::Value(rapidjson::kObjectType);
            pending_field.clear();
        };

        while (getline(strStrm, strLine, delimiter))
        {
            if (global.maxAllowedRules && total_rules > global.maxAllowedRules)
                break;

            strLine = trimWhitespace(strLine, true, true);
            const std::string::size_type lineSize = strLine.size();
            if (!lineSize || strLine[0] == ';' || strLine[0] == '#' ||
                (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/'))
                continue;
            if (strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }

            if (strLine == "FINAL" || strLine == "MATCH")
            {
                final = rule_group;
                continue;
            }

            const SingBoxClashRule parsed = parseSingBoxClashRule(strLine);
            if (parsed.kind == SingBoxClashRule::Kind::Final)
            {
                final = rule_group;
                continue;
            }
            if (parsed.kind == SingBoxClashRule::Kind::Geo)
            {
                flush_pending();
                if (appendSingBoxGeoRule(base_rule, rules, parsed.geo, parsed.value, rule_group, reject,
                                         allocator))
                    total_rules++;
                continue;
            }
            if (parsed.kind != SingBoxClashRule::Kind::Field)
                continue;

            if (parsed.scalar)
            {
                flush_pending();
                if (appendSingBoxFieldRule(rules, parsed, rule_group, reject, allocator))
                    total_rules++;
                continue;
            }

            if (pending_field != parsed.field)
                flush_pending();

            pending_field = parsed.field;

            if (parsed.numeric)
            {
                int number = 0;
                if (!parseSingBoxInt(parsed.value, number))
                    continue;

                if (!pending.HasMember(parsed.field.c_str()))
                    pending.AddMember(rapidjson::Value(parsed.field.c_str(), allocator),
                                      rapidjson::Value(rapidjson::kArrayType), allocator);
                pending[parsed.field.c_str()].PushBack(number, allocator);
            }
            else
            {
                if (!pending.HasMember(parsed.field.c_str()))
                    pending.AddMember(rapidjson::Value(parsed.field.c_str(), allocator),
                                      rapidjson::Value(rapidjson::kArrayType), allocator);
                pending[parsed.field.c_str()].PushBack(
                        rapidjson::Value(parsed.value.c_str(), parsed.value.size(), allocator), allocator);
            }

            total_rules++;
        }

        flush_pending();
    }

    if (final.empty() && base_rule.HasMember("route") && base_rule["route"].IsObject() &&
        base_rule["route"].HasMember("final") && base_rule["route"]["final"].IsString())
        final = base_rule["route"]["final"].GetString();

    if (!final.empty() && isSingBoxRejectGroup(final, reject_groups))
    {
        rapidjson::Value catch_all(rapidjson::kObjectType);
        catch_all.AddMember("action", "reject", allocator);
        catch_all.AddMember("method", "drop", allocator);
        rules.PushBack(catch_all, allocator);

        if (final == "REJECT" || final == "Reject")
            final = "DIRECT";
    }

    ensureSingBoxSystemRules(rules, allocator);
    ensureSingBoxRouteObject(base_rule, allocator);

    rapidjson::Value &route = base_rule["route"];
    if (route.HasMember("rules"))
        route["rules"].Swap(rules);
    else
        route.AddMember("rules", rules, allocator);

    if (!final.empty())
        route | AddMemberOrReplace("final", rapidjson::Value(final.c_str(), allocator), allocator);
    else if (!route.HasMember("final"))
        route.AddMember("final", "DIRECT", allocator);
    else if (route["final"].IsString() && std::string(route["final"].GetString()).empty())
        route["final"].SetString("DIRECT", allocator);

    setSingBoxDefaultDomainResolver(base_rule, allocator);
}
