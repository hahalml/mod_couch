Description: 

The module uses libcurl in the same way mod_xml_curl does
and connects to a given binding url where expects JSON
documents. Only URL formation and the specific parameters
passed to the backend make the module couchdb specific.

The module simply translates cURL-fetched JSON documents
to XML for internal switch parsing magic and could eventually
be turned into a generig cURL JSON module.

The motivation for hacking this module is to eliminate
the middle software layer between the distributed database
backend and the switch.

Sample document format:

```json
{
    "_id":"3156887333",
    "_rev":"946B7D1C",
    "document" : {
        "@type": "freeswitch/xml",
        "section": {
            "@name": "directory",
            "domain: {
                "@name": "server.domain.tld",
                "params": {
                    "param": {
                        "@name": "dial-string",
                        "@value": "{presence_id=${dialed_user}@${dialed_domain}}${sofia_contact(${dialed_user}@${dialed_domain})}",
                     }
                },
                "groups": {
                    "group": {
                        "@name": "default",
                        "users": {
                            "user": {
                                "@id": "1004",
                                "params": {
                                    "param": {
                                        "@name": "password",
                                        "@value": "some_password",
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
```

                
And thecorresponding XML generated equivallent would be:

```xml
<document type="freeswitch/xml">
  <section name="directory">
    <domain name="domain1.awesomevoipdomain.faketld">
      <params>
        <param name="dial-string" value="{presence_id=${dialed_user}@${dialed_domain}}${sofia_contact(${dialed_user}@${dialed_domain})}"/>
      </params>
      <groups>
        <group name="default">
         <users>
          <user id="1004">
            <params>
              <param name="password" value="some_password"/>
            </params>
          </user>
         </users>
        </group>
      </groups>
    </domain>
  </section>
</document>
```

Translation is based in Badgerfish convention: http://www.sklar.com/badgerfish/

Sample binding configuration:

N/A

