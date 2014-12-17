#
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# CMS File Lister
#
# Author: hasherezade (http://hasherezade.net)
# Source: https://github.com/hasherezade/metasploit_modules
#

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "CMS File Lister",
      'Description'    => %q{
          This auxiliary module attempts to list remote directory by comparision with local directory (or paths list)
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'hAsh (http://hasherezade.net)' # Metasploit module
        ]
    ))

    register_options(
    [
      OptPath.new('CMS_DIR',[false, 'Directory with CMS']),
      OptPath.new('PATH', [false, 'File with list of files to search']),
      OptString.new('TARGETURI', [true, 'URI of the lookup service', '/']),
      OptRegexp.new('NOT_FOUND', [true, '404 pattern', '/Not Found/']),
      OptRegexp.new('EXCLUDE_NAMES', [true, 'Skip files with names matching the pattern','\.(?:php|js|css|png|jpg|gif)$']),
      OptBool.new('DISPLAY_ERR', [true, 'Display error codes (if different than 404)', 'false']),
      OptBool.new('COMPARE_FILES', [true, 'Compare remote file with local','true'])
    ])
    deregister_options('VHOST', 'Proxies')
  end

# utils
  def read_dir(dir)
    return nil if not dir

    if not File::directory?(dir)
      print_error("Not a directory: #{dir}")
      return nil
    end

    files = Set.new

    Dir[ File.join(dir, '**', '*') ].reject { |p| File.directory? p
      full_path = "#{p}"
      dir_path = "#{dir}"
      suffix = full_path[dir_path.length, full_path.length - dir_path.length]
      if File::directory?(full_path)
        suffix += '/'
      end
      files << suffix
  }
  return files
  end

  def read_file(path)
    if not File::exist?(path)
      print_error("No such file: #{path}")
      return nil
    elsif not File::file?(path)
      print_error("Invalid path: #{path}")
      return nil
    end

    paths = Set.new
    my_file = File::new(path, mode="r")
    my_file.each {|line|
      line = line.strip
      if line
         paths << line
      end
      }
    my_file.close
    print_status("Found paths: #{paths.length}")
    return paths
  end

  def process_page_error(url, res_code, res_body)
    verbose = datastore['VERBOSE']
    if verbose == false
      return nil if res_code == 404
    end

    if datastore['DISPLAY_ERR']
      print_error("#{url} : #{res_code}")
    end
  end

  def get_url(path)
    port = datastore['RPORT']
    proto = "http"
    if (datastore['SSL'] == true)
      proto = "https"
    end
    url = "#{proto}:/" + normalize_uri("#{datastore['RHOST']}//#{datastore['TARGETURI']}//#{path}")
  end

  def compare_content(path, res_body)
    path = datastore['CMS_DIR'] + "/" + path

    if not File::exist?(path)
      print_error("Not existing local file: #{path}")
      return -1
    elsif File::directory?(path)
      return 1
    elsif not File::file?(path)
      return -1
    end
    contents = File.read(path)
    return 1 if res_body == contents
    return 0
  end

  def path_search(path)
    if not path
      return nil
    end

    port = datastore['RPORT']
    old_ssl = autoenable_ssl(port)
    url = get_url(path)

    res = send_request_cgi({
        'method' => 'GET',
        'uri'    => url,
        'rhost' => datastore['RHOST'],
        'rport' => datastore['RPORT']
    })
    datastore['SSL'] = old_ssl

    if res and res.code == 200 and not res.body =~ datastore['NOT FOUND']
      is_same = -1
      if datastore['COMPARE_FILES']
        is_same = compare_content(path, res.body)
      end

      verified = '[?]'
      if is_same == 1
        verified = '[+]'
      elsif is_same == 0
        verified = '[!]'
      end

      print_good("#{verified} #{url}")
      return true
    end
    if res
      process_page_error(url, res.code, res.body)
    else
      print_error("#{url}")
    end
    return false
  end

  def skip_type(path)
    if path =~ datastore['EXCLUDE_NAMES']
      return true
    end
    return false
  end

  def search_paths(paths)
    return nil if not paths

    found = 0
    for chunk in paths
      if skip_type(chunk)
        next
      end
      pass = path_search(chunk)
      if pass
        found += 1
      end
    end
    print_status("Found paths: #{found} out of #{paths.length}")
  end

  def autoenable_ssl(port)
    old_ssl = datastore['SSL']
    if (port == 80)
      datastore['SSL'] = false
    elsif (port == 443)
      datastore['SSL'] = true
    end
    return old_ssl
  end

# MSF API:

  def run
    paths = nil
    verbose = datastore['VERBOSE']
    print_status("Verbose mode: #{verbose}")

    if datastore['PATH']
      fname = datastore['PATH']
      print_status("Searching by list, PATH = #{fname}")
      paths = read_file(fname)
      print_status("Attempting to search paths...")
      search_paths(paths)
    else
      print_error('PATH not set!')
    end

    if datastore['CMS_DIR']
      cms = datastore['CMS_DIR']
      print_status("Searching by CMS_DIR = #{cms}")
      paths = read_dir(cms)
      search_paths(paths)
    else
      print_error('CMS_DIR not set!')
    end
  end

end

