function getlogs(id) {
    if (id) {
      $.ajax({
        type: "get",
        url: "/get_log",
        data: "id=" + id,
        success: function (data) {
          if (data) {
            if (data.error) {
              data = data.error.replace(/\n/g, "<br>");
              $("#logs").html(data);
            } else if (data.log) {
              txt = data.log.replace(/\n/g, "<br>");
              $("#logs").html(txt);
              //$("#main_log_div").scrollTop($("#logs").height());
            } else {
              $("#logs").html("No Log to display");
            }
          }
        },
        error: function (data) {
          if (typeof data === "string") {
            $("#logs").html(data.replace(/\n/g, "<br>"));
          }
        },
      });
    }
  }

  function getAllLogFiles() {
    $.ajax({
      type: "get",
      url: "/get_all_log_files",
      success: function (data) {
        if (data) {
          if (data.error) {
            $("#logs").html(data.error);
          } else {
            $("#nav_all_logs").html("");
            for (var i = 0; i < data["log_files"].length; i++) {
              generate_log_file_list_item(data["log_files"][i], i);
            }
          }
        }
      },
      error: function (data) {
        if (data) {
          $("#logs").html(data); //.replace(/\n/g, "<br>"));
        }
      },
    });
  }

  function getMachineUsage() {
    $.ajax({
      type: "get",
      url: "/usage",
      success: function (data) {
        if (data) {
          $("#machineusage").html(
            "cpu: " + data.cpu + "% | mem: " + data.memory + "%"
          );
        } else {
          $("#machineusage").html("cpu: N/A | mem: N/A");
        }
      },
      error: function (data) {
        $("#machineusage").html("cpu: N/A | mem: N/A");
      },
    });
  }

  function getAllCollectes() {
    $.ajax({
      type: "get",
      url: "/get_all_collectes",
      success: function (data) {
        if (data) {
          if (data.error) {
            $("#logs").html(data.error);
          } else {
            $("#nav_collectes").html("");
            for (const [key, value] of Object.entries(data)) {
              generate_collecte_list_item(value, key);
            }
          }
        }
      },
      error: function (data) {
        if (data) {
          $("#logs").html(data); //.replace(/\n/g, "<br>"));
        }
      },
    });
  }

  function getAllClients() {
    $.ajax({
      type: "get",
      url: "/get_all_clients_collectes",
      success: function (data) {
        if (data) {
          if (data.error) {
            $("#logs").html(data.error);
          } else {
            $("#nav_collectes").html("");
            for (const [key, val] of Object.entries(data)) {
              generate_clients_list_item(key, JSON.stringify(val));
            }
          }
        }
      },
      error: function (data) {
        if (data) {
          $("#logs").html(data); //.replace(/\n/g, "<br>"));
        }
      },
    });
  }

  function getOpenCollecteById(id) {
    if (confirm("Ré-ouvrir la collecte ?") == false) {
      return;
    }
    if (id) {
      $("#loading_div").show();
      $.ajax({
        type: "get",
        url: "/open_collecte_by_id",
        data: "id=" + id,
        success: function (data) {
          $("#loading_div").hide();
          if (data) {
            if (data.error) {
              generate_toast("open_collecte_" + id, data.error);
            }
            if (data.message) {
              generate_toast("open_collecte_" + id, data.message);
            }
            window.location.href = "/collecte/"+id;
          }
        },
        error: function (data) {
          if (data) {
            $("#logs").html(data);
          }
          $("#loading_div").hide();
        },
      });
    }
  }

  function getClientCollectes(collectes, clientName) {
    if (collectes) {
      collectes = JSON.parse(collectes);
      $("#offcanvasClientUl").html("");
      for (const [key, val] of Object.entries(collectes)) {
        generate_collecte_list_item(val, key);
      }
      $("#offcanvasClientLabel").html(clientName);
      //onst bsOffcanvas = new bootstrap.Offcanvas('#offcanvasClient');
      //bsOffcanvas.show();
      var myOffcanvas = document.getElementById("offcanvasClient");
      var bsOffcanvas = new bootstrap.Offcanvas(myOffcanvas).show();
    }
  }

  function getCollecte(id) {
    if (id) {
      $("#loading_div").show();
      var myOffcanvas = document.getElementById("offcanvasClient");
      var bsOffcanvas = new bootstrap.Offcanvas(myOffcanvas).hide();
      $.ajax({
        type: "get",
        url: "/get_collecte",
        data: "id=" + id,
        success: function (data) {
          $("#loading_div").hide();
          if (data) {
            populate_form(data);
            getlogs(data.uuid);
          }
        },
        error: function (data) {
          $("#loading_div").hide();
          if (data) {
            $("#logs").html(data); //replace(/\n/g, "<br>"));
          }
        },
      });
    }
  }

  function getRunningCollectes(mainpage=true, uuid="") {
    $.ajax({
      type: "get",
      url: "/get_running_collectes",
      success: function (data) {
        if (data) {
          if (data.running) {
            if(mainpage){
              populate_running_form(data);
            }
            else{
              collecte_page_running(data, uuid);
            }
            
          }
        }
      },
      error: function (data) {
        if (data) {
          $("#logs").html(data); //replace(/\n/g, "<br>"));
        }
      },
    });
  }

  function get_collecte_status(task_id) {
    if(task_id){
      $.ajax({
        type: "get",
        url: "/get_collecte_status",
        data: "task_id=" + task_id,
        success: function (data) {
          if (data) {
            if (data.task_status === 'STARTED') {
              $("#collecte_running_div").show();
              $("#download_results_div").hide();
              $("#replayForm").hide();
            }
            else if (data.task_status === 'SUCCESS' || data.task_status === 'FAILURE') {
              $("#collecte_running_div").hide();
              $("#download_results_div").show();
              $("#replayForm").show();
            }
            else{
              $("#collecte_running_div").hide();
              $("#download_results_div").hide();
              $("#replayForm").show();
            }
          }
        },
        error: function (data) {
          console.log(data)
        },
      });
    }
    else{
      $("#collecte_running_div").hide();
      $("#download_results_div").hide();
      $("#replayForm").show();
    }
  }


  function downloadCollecte(id, collecte_name = "") {
    if (id) {
      $.ajax({
        type: "get",
        url: "/download",
        data: "id=" + id,
        success: function (data) {
          if (data) {
            const file = new File([data], collecte_name);
          }
          generate_toast("download", "Fichier téléchargé en totalité");
        },
        error: function (data) {
          if (data) {
            $("#logs").html(data); //.replace(/\n/g, "<br>"));
          }
        },
      });
    }
  }

  function start_process(params) {
    //$("#logs").html("Processing...");
    $.ajax({
      type: "POST",
      url: "/process",
      data: JSON.stringify(params),
      contentType: "application/json",
      success: function (data) {
        if (data.error) {
          $("#logs").html(data.error);
        } else if (data.message) {
          generate_toast("queueing", data.message);
        } else if (data.uuid) {
          getlogs(data.uuid);
          get_collecte_status(data.task_id)
          if (_myconfig)
          {
            _myconfig.task_id = data.task_id
            $("#collecte_task_value").html(_myconfig.task_id);
          }
          $("#download_results_div").show();
        }
      },
      error: function (data) {
        if (data.error) {
          $("#logs").html(data.error);
        }
      },
    });
  }

  function getAllKeysLocalStorage() {
    return Object.keys(localStorage);
  }

  function delLocalStorage(key) {
    localStorage.removeItem(key);
  }

  function generate_toast(id, text, s_class = "") {
    $("#alltoasts").append(
      '\
  <div id="' +
        id +
        '" class="toast ' +
        s_class +
        '" role="alert" aria-live="assertive" aria-atomic="true" data-autohide="false">\
    <div class="toast-header">\
      <strong class="me-auto">Triage</strong>\
      <small class="text-body-secondary">now</small>\
    </div>\
    <div id="' +
        id +
        '_body" class="toast-body">' +
        text +
        "\
    </div>\
  </div>\
  "
    );
    $("#" + id).toast("show");
  }

  function generate_clients_list_item(htmltext, value) {
    $("<button/>", {
      text: htmltext,
      id: "nav_collectes_" + htmltext,
      collectes: value,
      class: "dropdown-item",
    }).appendTo(
      $("<li/>", {
        id: "li_nav_collectes_" + value,
      }).appendTo($("#nav_collectes"))
    );
    $("#nav_collectes_" + htmltext).click(function (e) {
      getClientCollectes(this.getAttribute("collectes"), htmltext);
    });
  }

  function generate_collecte_list_item(htmltext, value) {
    $("<button/>", {
      text: htmltext,
      id: "btn_canvas_" + value,
      collecte: value,
      "data-bs-dismiss": "offcanvas",
      class: "list-group-item list-group-item-action",
    }).appendTo(
      $("<li/>", {
        class: "list-group-item",
        id: "li_canvas_" + value,
      }).appendTo($("#offcanvasClientUl"))
    );

    $("#btn_canvas_" + value).click(function (e) {
      //getCollecte(this.getAttribute("collecte"));
      location.href = "/collecte/"+this.getAttribute("collecte");
    });
  }

  function generate_closed_collectes_list_item(htmltext, value) {
    $("<button/>", {
      text: htmltext,
      id: "nav_closed_collectes_" + value,
      collectes: value,
      class: "dropdown-item",
    }).appendTo(
      $("<li/>", {
        id: "li_nav_closed_collectes_" + value,
      }).appendTo($("#nav_closed_collectes"))
    );
    $("#nav_closed_collectes_" + value).click(function (e) {
      //getOpenCollecteById(this.getAttribute("collectes"));
      window.location.href = "/collecte/"+this.getAttribute("collectes");
    });
  }

  function generate_log_file_list_item(htmltext, value) {
    $("<a/>", {
      text: htmltext,
      id: "nav_log_file_" + value,
      log_file: htmltext,
      class: "dropdown-item",
      href: "/download_log_file?id=" + htmltext,
    }).appendTo(
      $("<li/>", {
        id: "li_nav_log_file_" + value,
      }).appendTo($("#nav_all_logs"))
    );
  }

  function populate_form(config) {
    if (config) {
      $("#input_client_name").val(config.general.client);
      $("#input_client_name").prop("disabled", true);
      $("#input_hostname").val(config.general.hostname);
      $("#input_hostname").prop("disabled", true);
      $("#input_timesketch_id").val(config.general.timesketch_id);
      $("#input_timesketch_id").prop("disabled", true);
      
      if (config.run.kape.plugin == true) {
        $("#kape_sub_modules").show();
      } else {
        $("#kape_sub_modules").hide();
      }
      $("#run_kape").prop("checked", config.run.kape.plugin);
      $("#run_kape_evtx").prop("checked", config.run.kape.evtx);
      $("#run_kape_iis").prop("checked", config.run.kape.iis);
      $("#run_kape_timeline").prop("checked", config.run.kape.timeline);
      $("#kape_evtx_winlogbeat").prop("checked", config.run.kape.winlogbeat);

      $("#run_hayabusa").prop("checked", config.run.hayabusa);
      $("#run_adtimeline").prop("checked", config.run.adtimeline);
      $("#run_o365").prop("checked", config.run.o365);
      
      $("#run_orc").prop("checked", config.run.orc.plugin);
      $("#run_adaudit").prop("checked", config.run.adaudit.plugin);

      $("#run_mail").prop("checked", config.run.mail.plugin);
      if (config.run.mail.plugin == true) {
        $("#mail_sub_modules").show();
        $("#run_mail_attachments").prop("checked", config.run.mail.attachments);
      } else {
        $("#mail_sub_modules").hide();
      }

      if (config.run.uac.plugin == true) {
        $("#uac_sub_modules").show();
      } else {
        $("#uac_sub_modules").hide();
      }
      $("#run_uac").prop("checked", config.run.uac.plugin);
      $("#run_uac_filebeat").prop("checked", config.run.uac.filebeat);
      $("#run_uac_timeline").prop("checked", config.run.uac.timeline);

      if (config.run.volatility.plugin == true) {
        $("#volatility_sub_modules").show();
      } else {
        $("#volatility_sub_modules").hide();
      }
      $("#run_volatility").prop("checked", config.run.volatility.plugin);
      $("#run_volatility_pslist").prop(
        "checked",
        config.run.volatility.pslist
      );
      $("#run_volatility_pstree").prop(
        "checked",
        config.run.volatility.pstree
      );
      $("#run_volatility_netscan").prop(
        "checked",
        config.run.volatility.netscan
      );
      $("#run_volatility_netstat").prop(
        "checked",
        config.run.volatility.netstat
      );

      if (config.run.generaptor.plugin == true) {
        $("#generaptor_sub_modules").show();
        $("#run_generaptor").prop("checked", config.run.generaptor.plugin);
        $("#run_generaptor_evtx").prop("checked", config.run.generaptor.evtx);
        $("#generaptor_evtx_winlogbeat").prop("checked", config.run.generaptor.winlogbeat);
        $("#run_generaptor_iis").prop("checked", config.run.generaptor.iis);
        $("#run_generaptor_timeline").prop(
          "checked",
          config.run.generaptor.timeline
        );
        $("#run_generaptor_linux").prop(
          "checked",
          config.run.generaptor.linux
        );
      } else {
        $("#generaptor_sub_modules").hide();
      }

      if (config.run.standalone) {
        $("#run_standalone").prop("checked", config.run.standalone.plugin);
        if (config.run.standalone.plugin == true) {
          $("#run_standalone_li").show();
          _lbl = "Standalone: ";
          for (var _k in config.run.standalone) {
            if (config.run.standalone.hasOwnProperty(_k)) {
              if (config.run.standalone[_k]) {
                if (_k != "plugin") {
                  _lbl += _k + " ";
                  $("#run_standalone_plugin").attr(
                    "name",
                    "standalone_" + _k
                  );
                  $("#run_standalone_plugin").prop("checked", true);
                }
              }
            }
          }
          $("#run_standalone_label").html(_lbl);
        } else {
          console.log("hide");
          $("#run_standalone_li").hide();
          $("#run_standalone_label").html("Standalone not set");
        }
      }

      $("#archive_file").hide();

      $("#download_btn_div").html(
        '<a id="download_collecte_a" class="btn btn-outline-primary my-2 my-sm-0" href="/download?id=' +
          config.uuid +
          '">Télécharger la collecte</a>'
      );
      $("#download_infos_div").html(
        '<pre style="margin-bottom:0rem;padding-top:1rem;">Nom: ' +
          config.archive.name +
          '</pre>\
    <pre style="margin-bottom:0rem;">SHA256: ' +
          config.archive.sha256 +
          "</pre>\
    <pre>UUID: " +
          config.uuid +
          "</pre>"
      );
      $("#download_div").show();

      $("#standalone_collecte").hide();
      $("#replayForm").show();
      $("#submitForm").hide();
    }
  }

  function reset_form() {
    $("#input_client_name").val("");
    $("#input_client_name").prop("disabled", false);
    $("#input_hostname").val("");
    $("#input_hostname").prop("disabled", false);
    $("#input_timesketch_id").val("");
    $("#input_timesketch_id").prop("disabled", false);
    
    $("#kape_sub_modules").show();
    $("#run_kape").prop("checked", true);
    $("#run_kape_evtx").prop("checked", true);
    $("#run_kape_iis").prop("checked", true);
    $("#run_kape_timeline").prop("checked", true);
    $("#kape_evtx_winlogbeat").prop("checked", true);

    $("#run_hayabusa").prop("checked", true);
    $("#run_adtimeline").prop("checked", false);
    $("#run_o365").prop("checked", false);
    
    $("#run_mail").prop("checked", false);
    $("#mail_sub_modules").hide();

    $("#run_orc").prop("checked", false);

    $("#run_adaudit").prop("checked", false);

    $("#uac_sub_modules").show();

    $("#uac_sub_modules").hide();
    $("#run_uac").prop("checked", false);
    $("#run_uac_filebeat").prop("checked", false);
    $("#run_uac_timeline").prop("checked", false);

    $("#volatility_sub_modules").hide();
    $("#run_volatility").prop("checked", false);
    $("#run_volatility_pstree").prop("checked", false);
    $("#run_volatility_pslist").prop("checked", false);
    $("#run_volatility_netscan").prop("checked", false);
    $("#run_volatility_netstat").prop("checked", false);

    $("#generaptor_sub_modules").hide();
    $(".generaptor_sub_modules").prop("checked", false);
    $("#run_generaptor").prop("checked", false);
    $("#run_generaptor_evtx").prop("checked", false);
    $("#generaptor_evtx_winlogbeat").prop("checked", false);
    $("#run_generaptor_iis").prop("checked", false);
    $("#run_generaptor_timeline").prop("checked", false);
    $("#run_generaptor_linux").prop("checked", false);
    $("#run_generaptor_private_key_file").prop("required", false);
    $("#run_generaptor_private_key_file").val("");
    $("#run_generaptor_private_key_secret").prop("required", false);
    $("#run_generaptor_private_key_secret").val("");
    $(".generaptor_plugin").hide();

    $("#run_standalone").prop("checked", false);
    $("#run_standalone_li").hide();

    $("#archive_file").show();

    $("#standalone_collecte").show();

    $("#replayForm").hide();
    $("#submitForm").show();
  }

  function populate_running_form(data) {
    text = "";
    for (let i = 0; i < data.running.length; i++) {
      text +=
        '<h4 class="card-title">Client: ' + data.running[i].client + "</h4>";
      text +=
        '<p class="card-text">Machine: ' + data.running[i].hostname + "</p>";
    }
    $("#running_collecte_div").html(text);
  }

  function collecte_page_running(data, uuid) {
    text = "";
    $("#download_results_div").show();
    $("#replayForm").show();
    $("#collecte_running_div").hide();
    for (let i = 0; i < data.running.length; i++) {
      if(data.running[i].uuid == uuid){
        $("#collecte_running_div").show();
        $("#download_results_div").hide();
        $("#replayForm").hide();
      }
    }
  }

  function check_config() {
    var ret = true;
    var plugin_selected = $("#select_plugin").find(":selected").val();
    ret &= $("#input_client_name").val() ? true : false;
    if(!$("#input_client_name").val()){$("#input_client_name").addClass('is-invalid');}
    else{$("#input_client_name").removeClass('is-invalid');}
    
    ret &= $("#input_hostname").val() ? true : false;
    if(!$("#input_hostname").val()){$("#input_hostname").addClass('is-invalid');}
    else{$("#input_hostname").removeClass('is-invalid');}
    
    ret &= $("#archive").val() ? true : false;
    if(!$("#archive").val()){$("#archive").addClass('is-invalid');}
    else{$("#archive").removeClass('is-invalid');}
    
   switch(plugin_selected){
    case "generaptor":
      ret &= $("#run_generaptor_private_key_file").val() ? true : false;
      if(!$("#run_generaptor_private_key_file").val()){$("#run_generaptor_private_key_file").addClass('is-invalid');}
      else{$("#run_generaptor_private_key_file").removeClass('is-invalid');}
      ret &= $("#run_generaptor_private_key_secret").val() ? true : false;
      if(!$("#run_generaptor_private_key_secret").val()){$("#run_generaptor_private_key_secret").addClass('is-invalid');}
      else{$("#run_generaptor_private_key_secret").removeClass('is-invalid');}
      break;
    case "orc":
      ret &= $("#run_orc_certfile").val() ? true : false;
      if(!$("#run_orc_certfile").val()){$("#run_orc_certfile").addClass('is-invalid');}
      break;
   }
    return ret;
  }

  function check_config_modal() {
    var ret = true;
    ret &= $("#standaloneModal_input_client_name").val() ? true : false;
    if(!$("#standaloneModal_input_client_name").val()){$("#standaloneModal_input_client_name").addClass('is-invalid');}
    else{$("#standaloneModal_input_client_name").removeClass('is-invalid');}
    
    ret &= $("#standaloneModal_input_hostname").val() ? true : false;
    if(!$("#standaloneModal_input_hostname").val()){$("#standaloneModal_input_hostname").addClass('is-invalid');}
    else{$("#standaloneModal_input_hostname").removeClass('is-invalid');}

    ret &= $("#standaloneModal_run_plugin").val() ? true : false;
    if(!$("#standaloneModal_run_plugin").val()){$("#standaloneModal_run_plugin").addClass('is-invalid');}
    else{$("#standaloneModal_run_plugin").removeClass('is-invalid');}

    ret &= $("#standaloneModal_file").val() ? true : false;
    if(!$("#standaloneModal_file").val()){$("#standaloneModal_file").addClass('is-invalid');}
    else{$("#standaloneModal_file").removeClass('is-invalid');}

    return ret;
  }

  function populate_plugins_infos(data) {
    var text = "";
    if (!data.general.client){return;}
    for (key in data.run) {
      if (typeof data.run[key] == "boolean") {
        _name = key;
        _executed = data.run[key];
        if (_executed) {
          _checked = data.run[key] ? "checked" : "";
          text +=
            '<div id="collecte_plugin_' +
            _name +
            '_row" class="row"><pre id="collecte_plugin_name_' +
            _name +
            '_title" class="col-3">' +
            _name +
            '</pre><div class="form-check form-switch col-9"><input class="form-check-input" type="checkbox" role="switch" id="collecte_plugin_name_' +
            _name +
            '_chkbox" ' +
            _checked +
            " onclick=\"update_plugin_config('" +
            _name +
            "', '', " +
            !_checked +
            ')" /></div></div>';
        }
      } else {
        if (data.run[key].plugin) {
          _excluded = ["plugin", "private_key_secret", "private_key_file"];
          text +=
            '<div id="collecte_plugin_' +
            key +
            '_row" class="row"><pre id="collecte_plugin_name_' +
            key +
            '_title" class="col-3">Name</pre><pre id="collecte_plugin_name_' +
            key +
            '_value"  class="col-9">' +
            key +
            "</pre></div>";
          for (subkey in data.run[key]) {
            if (!_excluded.includes(subkey)) {
              _checked = data.run[key][subkey] ? "checked" : "";
              text +=
                '<div id="collecte_plugin_' +
                subkey +
                '_row" class="row"><pre id="collecte_plugin_name_' +
                subkey +
                '_title" class="col-3">' +
                subkey +
                '</pre><div class="form-check form-switch col-9"><input class="form-check-input" type="checkbox" role="switch" id="collecte_plugin_name_' +
                subkey +
                '_chkbox" ' +
                _checked +
                " onclick=\"update_plugin_config('" +
                key +
                "', '" +
                subkey +
                "', " +
                !_checked +
                ')" /></div></div>';
            }
          }
        }
      }
    }
    $("#collecte_plugins_div").html(text);
  }

  function update_plugin_config(plugin_name, plugin_option, new_value) {
    if (plugin_option) {
      if(plugin_option == "winlogbeat" && new_value && !_myconfig.run[plugin_name]["evtx"]){
        _myconfig.run[plugin_name]["evtx"] = true;
        _myconfig.run[plugin_name][plugin_option] = new_value;
      }
      else if(plugin_option == "evtx" && !new_value){
        _myconfig.run[plugin_name]["winlogbeat"] = false;
        _myconfig.run[plugin_name][plugin_option] = new_value;
      }
      else{
        _myconfig.run[plugin_name][plugin_option] = new_value;
      }
      populate_plugins_infos(_myconfig);
    } else {
      _myconfig.run[plugin_name] = new_value;
      populate_plugins_infos(_myconfig);
    }
  }

