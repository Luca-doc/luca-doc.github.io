<?php if (!defined('ABSPATH')) die();

class Agency_model extends MVC_model {
  function get_contact_email_address($agency = 'hq') {
    $agencies = $this->get_list();

    if (isset($agencies[$agency]) && $agencies[$agency]['is_integrated'] == true && strlen($agencies[$agency]['contact_email_address']) > 0) {
      return $agencies[$agency]['contact_email_address'];
    }
    else {
      return $agencies['hq']['contact_email_address'];
    }
  }
  function get_list() {
    /** Key names and their meaning:
     * label - the full name of the agency
     * abbreviation - short name, such as HMCTS
     * url - url of the external site that goes into the My MoJ section
     * url_label - alternative label on the external link; label is used as fallback
     * blog url - custom url for main menu blog
     * is_integrated - whether the agency is already integrated into the intranet or not
     */
    return array(
      'cica' => array(
        'label' => 'Criminal Injuries Compensation Authority',
        'abbreviation' => 'CICA',
        'url' => '',
        'is_integrated' => true,
        'is_external' => false
      ),
      'pb' => array(
        'label' => 'Parole Board',
        'abbreviation' => 'PB',
        'url' => '',
        'is_integrated' => true,
        'is_external' => false
      ),
      'hmcts' => array(
        'label' => 'HM Courts &amp; Tribunals Service',
        'abbreviation' => 'HMCTS',
        'url' => 'http://hmcts.intranet.service.justice.gov.uk/hmcts/',
        'url_label' => 'HMCTS Archive intranet',
        'blog_url' => 'http://hmcts.blogs.justice.gov.uk',
        'is_integrated' => true,
        'is_external' => true
      ),
      'judicial-appointments-commission' => array(
        'label' => 'Judicial Appointments Commission',
        'abbreviation' => 'JAC',
        'url' => 'http://jac.intranet.service.justice.gov.uk/',
        'is_integrated' => false,
        'is_external' => true
      ),
      'judicial-office' => array(
        'label' => 'Judicial Office',
        'abbreviation' => 'JO',
        'url' => 'http://judicialoffice.intranet.service.justice.gov.uk/',
        'is_integrated' => false,
        'is_external' => true
      ),
      'law-commission' => array(
        'label' => 'Law Commission',
        'abbreviation' => 'LawCom',
        'url' => 'http://lawcommission.intranet.service.justice.gov.uk/',
        'is_integrated' => false,
        'is_external' => true
      ),
      'laa' => array(
        'label' => 'Legal Aid Agency',
        'abbreviation' => 'LAA',
        'url' => '',
        'is_integrated' => true,
        'is_external' => true,
        'contact_email_address' => 'intranet-laa@digital.justice.gov.uk'
      ),
      'hq' => array(
        'label' => 'Ministry of Justice HQ',
        'abbreviation' => 'MoJ',
        'url' => site_url('/about-us/moj-transformation/'),
        'url_label' => 'MoJ TRANSFORMATION &#8594;',
        'is_integrated' => true,
        'default' => true,
        'is_external' => false,
        'classes' => 'transformation',
        'contact_email_address' => 'intranet@justice.gsi.gov.uk'
      ),
      'noms' => array(
        'label' => 'National Offender Management Service',
        'abbreviation' => 'NOMS',
        'url' => 'https://intranet.noms.gsi.gov.uk/',
        'is_integrated' => false,
        'is_external' => true
      ),
      'nps' => array(
        'label' => 'National Probation Service',
        'abbreviation' => 'NPS',
        'url' => 'https://intranet.noms.gsi.gov.uk/',
        'is_integrated' => false,
        'is_external' => true
      ),
      'opg' => array(
        'label' => 'Office of the Public Guardian',
        'abbreviation' => 'OPG',
        'url' => '',
        'is_integrated' => true,
        'is_external' => true,
        'contact_email_address' => 'intranet-opg@digital.justice.gov.uk'
      ),
      'ospt' => array(
        'label' => 'Official Solicitor and Public Trustee',
        'abbreviation' => 'OSPT',
        'url' => 'http://intranet.justice.gsi.gov.uk/ospt/index.htm',
        'is_integrated' => false,
        'is_external' => true
      )
    );
  }
  private function _get_agencies() {
    /** Key names and their meaning:
     * label - the full name of the agency
     * abbreviation - short name, such as HMCTS
     * url - url of the external site that goes into the My MoJ section
     * url_label - alternative label on the external link; label is used as fallback
     * blog url - custom url for main menu blog
     * is_integrated - whether the agency is already integrated into the intranet or not
     */
    return array(
        'cica' => array(
            'label' => 'Criminal Injuries Compensation Authority',
            'abbreviation' => 'CICA',
            'is_integrated' => true,
            'links' => []
        ),
        'pb' => array(
            'label' => 'Parole Board',
            'abbreviation' => 'PB',
            'url' => '',
            'is_integrated' => true,
            'is_external' => false
        ),
        'hmcts' => array(
            'label' => 'HM Courts &amp; Tribunals Service',
            'abbreviation' => 'HMCTS',
            'blog_url' => 'http://hmcts.blogs.justice.gov.uk',
            'is_integrated' => true,
            'links' => [
                [
                    'url' => 'http://hmcts.intranet.service.justice.gov.uk/hmcts/',
                    'label' => 'HMCTS Archive intranet',
                    'is_external' => true
                ],
                [
                    'url' => site_url('/about-hmcts/justice-matters/'),
                    'label' => 'Justice Matters',
                    'classes' => 'transformation'

                ]
            ]
        ),
        'judicial-appointments-commission' => array(
            'label' => 'Judicial Appointments Commission',
            'abbreviation' => 'JAC',
            'is_integrated' => false,
            'links' => [
                [
                    'url' => 'http://jac.intranet.service.justice.gov.uk/',
                    'label' => 'Judicial Appointments Commission intranet',
                    'is_external' => true
                ]
            ]
        ),
        'judicial-office' => array(
            'label' => 'Judicial Office',
            'abbreviation' => 'JO',
            'is_integrated' => false,
            'links' => [
                [
                    'url' => 'http://judicialoffice.intranet.service.justice.gov.uk/',
                    'label' => 'Judicial Office intranet',
                    'is_external' => true
                ]
            ]
        ),
        'law-commission' => array(
            'label' => 'Law Commission',
            'abbreviation' => 'LawCom',
            'is_integrated' => false,
            'links' => [
                [
                    'url' => 'http://lawcommission.intranet.service.justice.gov.uk/',
                    'label' => 'Law Commission intranet',
                    'is_external' => true
                ]
            ]
        ),
        'laa' => array(
            'label' => 'Legal Aid Agency',
            'abbreviation' => 'LAA',
            'is_integrated' => true,
            'contact_email_address' => 'intranet-laa@digital.justice.gov.uk',
            'url' => []
        ),
        'hq' => array(
            'label' => 'Ministry of Justice HQ',
            'abbreviation' => 'MoJ',
            'is_integrated' => true,
            'default' => true,
            'contact_email_address' => 'intranet@justice.gsi.gov.uk',
            'links' => [
                [
                    'url' => site_url('/about-us/moj-transformation/'),
                    'label' => 'MoJ TRANSFORMATION &#8594;',
                    'is_external' => false,
                    'classes' => 'transformation'
                ]
            ]
        ),
        'noms' => array(
            'label' => 'National Offender Management Service',
            'abbreviation' => 'NOMS',
            'is_integrated' => false,
            'links' => [
                [
                    'url' => 'https://intranet.noms.gsi.gov.uk/',
                    'label' => 'National Offender Management Service intranet',
                    'is_external' => true
                ]
            ]
        ),
        'nps' => array(
            'label' => 'National Probation Service',
            'abbreviation' => 'NPS',
            'is_integrated' => false,
            'links' => [
                [
                    'url' => 'https://intranet.noms.gsi.gov.uk/',
                    'label' => 'National Probation Service intranet',
                    'is_external' => true
                ]
            ]
        ),
        'opg' => array(
            'label' => 'Office of the Public Guardian',
            'abbreviation' => 'OPG',
            'is_integrated' => true,
            'contact_email_address' => 'intranet-opg@digital.justice.gov.uk',
            'links' => [
            ]
        ),
        'ospt' => array(
            'label' => 'Official Solicitor and Public Trustee',
            'abbreviation' => 'OSPT',
            'is_integrated' => false,
            'links' => [
                [
                    'url' => 'http://intranet.justice.gsi.gov.uk/ospt/index.htm',
                    'label' => 'Official Solicitor and Public Trustee intranet',
                    'is_external' => true
                ]
            ]
        )
    );
  }
}
