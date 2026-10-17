<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:output method="xml"
              omit-xml-declaration="yes"
              indent="yes"/>

  <!-- Identity transform -->
  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
  </xsl:template>

  <!-- Mark OVS-backed domain interfaces explicitly -->
  <xsl:template match="/domain/devices/interface[@type='bridge']">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>

      <xsl:if test="
        not(virtualport)
        and (
          source/@bridge='ovs-monitor'
          or source/@bridge='ovs-targets'
          or source/@bridge='ovs-attack'
        )
      ">
        <virtualport type="openvswitch"/>
      </xsl:if>

    </xsl:copy>
  </xsl:template>

</xsl:stylesheet>
