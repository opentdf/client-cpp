<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xhtml="http://www.w3.org/1999/xhtml"
	xmlns:ism="urn:us:gov:ic:ism" xmlns:ntk="urn:us:gov:ic:ntk" xmlns:edh="urn:us:gov:ic:edh"
	xmlns:arh="urn:us:gov:ic:arh" exclude-result-prefixes="xs" version="2.0">

	<!-- **************************************************************** -->
	<!-- Identity template -->
	<!-- **************************************************************** -->
	<xsl:template match="@*|node()" name="identity">
		<xsl:copy>
			<xsl:apply-templates select="@*|node()" />
		</xsl:copy>
	</xsl:template>

	<xsl:template match="xs:import">
		<xs:import namespace="urn:us:gov:ic:edh" schemaLocation="../IC-EDH/IC-EDH.xsd" />
		<xs:import namespace="urn:us:gov:ic:arh" schemaLocation="../ARH/IC-ARH.xsd" />
	</xsl:template>

	<xsl:template match="//xs:complexType[@name='KeyAccessType']/xs:any">

	</xsl:template>

	<xsl:template
		match="//xs:complexType[@name='BindingInformationType']//xs:element[@ref='ds:KeyInfo']">

	</xsl:template>

	<xsl:template match="//xs:element[@name='HandlingStatement']//xs:any">
		<xs:choice>
			<xs:element ref="edh:Edh" minOccurs="1" maxOccurs="1" />
			<xs:element ref="edh:ExternalEdh" minOccurs="1" maxOccurs="1" />
		</xs:choice>
	</xsl:template>

	<xsl:template match="//xs:element[@name='StatementMetadata']//xs:any">

		<xs:choice>
			<xs:element ref="edh:Edh" minOccurs="1" maxOccurs="1" />
			<xs:element ref="edh:ExternalEdh" minOccurs="1" maxOccurs="1" />
			<xs:element ref="arh:Security" minOccurs="1" maxOccurs="1" />
			<xs:element ref="arh:ExternalSecurity" minOccurs="1"
				maxOccurs="1" />
		</xs:choice>
	</xsl:template>
	
	<xsl:template match="//xs:element[@name='EncryptionInformation']//xs:any">
	</xsl:template>

</xsl:stylesheet>