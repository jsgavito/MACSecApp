from jinja2 import Template

# Template for a CA deletion
deleteCA = Template('''
    <config>
        <macsec xmlns="http://www.ciena.com/ns/yang/ciena-macsec">
            <config>
                <connection-association xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                <name>{{CA}}</name>
                </connection-association>
            </config>
        </macsec>
    </config>
''')
# Template for MACSec profile deletion
deletePF = Template('''
    <config>
        <macsec xmlns="http://www.ciena.com/ns/yang/ciena-macsec">
            <macsec-profiles>
                <profile xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                <name>{{pf}}</name>
                </profile>
            </macsec-profiles>
        </macsec>
    </config>
''')

# Template for MACSec key chain deletion
deleteKC = Template('''
    <config>
        <macsec xmlns="http://www.ciena.com/ns/yang/ciena-macsec">
            <key-chains>
                <key-chain xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                <name>{{KC}}</name>
            </key-chain>
            </key-chains>
        </macsec>
    </config>
''')

# Template for FP deletion
deleteFP = Template('''
    <config>
        <fps xmlns="urn:ciena:params:xml:ns:yang:ciena-pn:ciena-mef-fp">
            <fp xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
            <name>{{FP}}</name></fp>
        </fps>
    </config>
''')


# Create config template for a key-chain
createKC= Template('''
<config>
    <macsec xmlns="http://www.ciena.com/ns/yang/ciena-macsec">
        <key-chains>
        <key-chain>
            <name>{{keyname}}</name>
            <mka-keys><mka-key>
            <name>01</name><key>{{newkey}}</key>
            <cryptographic-algorithm>AES_256_CMAC</cryptographic-algorithm>
            </mka-key></mka-keys>
        </key-chain>
        </key-chains>
    </macsec>
</config>
''')

# Create config template for a macsec-profile

createMSprofile= Template ('''
<config>
    <macsec xmlns="http://www.ciena.com/ns/yang/ciena-macsec">
        <macsec-profiles>
            <profile><name>{{pf}}</name>
            <replay-window-size>2</replay-window-size>
            <macsec-cipher-suite>GCM_AES_256</macsec-cipher-suite>
            <encryption-on>true</encryption-on>
            <sak-rekey-interval>{{keyinterval}}</sak-rekey-interval>
            </profile>
        </macsec-profiles>
    </macsec>
</config>
''')

#Create CA
createCA= Template('''
<config>
<macsec xmlns="http://www.ciena.com/ns/yang/ciena-macsec">
   <config>
     <connection-association><name>{{CA}}</name>
       <macsec-profile>{{pf}}</macsec-profile>
          <key-chain>{{keyname}}</key-chain>
          <flow-point>{{fp}}</flow-point>
          <destination-address>{{remotemac}}</destination-address>
          <mka-ethertype>36865</mka-ethertype> 
     </connection-association>
   </config>
</macsec>
</config>
''')

#    Enable MACSec config on interface 7 (only for first service)
###REVISAR ESTO
configIntMACSec= Template("""
<config>
        <macsec xmlns="http://www.ciena.com/ns/yang/ciena-macsec"><config>
            <interfaces><interface>
                <name>{{port}}</name>
                <strict-mode-on>false</strict-mode-on>
                <exclude-protocols>lldp</exclude-protocols>
        </interface></interfaces>
        </config>
    </macsec>
</config>
""")

# Create config template for a new classifier
createClassifier= Template('''
<config><classifiers>
    <classifier>
        <name>VLAN{{vid}}</name>
        <filter-entry>
        <filter-parameter xmlns:classifier="urn:ciena:params:xml:ns:yang:ciena-pn::ciena-mef-classifier">classifier:vtag-stack</filter-parameter>
            <vtags><tag>1</tag>
            <vlan-id>{{vid}}</vlan-id>
            </vtags>
        </filter-entry></classifier>
    </classifiers>
</config>
''')

# Create config template for a new forwarding domain
createFD= Template('''
<config>
    <fds xmlns="urn:ciena:params:xml:ns:yang:ciena-pn:ciena-mef-fd">
        <fd><name>FDVLAN{{vid}}</name>
            <mode>vpls</mode>
	        <vlan-id>{{vid}}</vlan-id>
	    </fd></fds>
</config>
''')


# Create config template for a new flow-point
createFP= Template('''
<config><fps xmlns="urn:ciena:params:xml:ns:yang:ciena-pn:ciena-mef-fp">
	<fp>
        <name>FPVLAN{{vid}}</name>
	    <fd-name>FDVLAN{{vid}}</fd-name>
	    <logical-port>{{port}}</logical-port>
	    <classifier-list>VLAN{{vid}}</classifier-list>
	</fp></fps>
</config>
''')




