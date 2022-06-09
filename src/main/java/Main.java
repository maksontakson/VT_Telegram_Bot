import com.kanishka.virustotal.dto.*;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;
import org.apache.commons.io.FileUtils;
import org.telegram.telegrambots.bots.TelegramLongPollingBot;
import org.telegram.telegrambots.meta.TelegramBotsApi;
import org.telegram.telegrambots.meta.api.methods.GetFile;
import org.telegram.telegrambots.meta.api.methods.send.SendDocument;
import org.telegram.telegrambots.meta.api.methods.send.SendMessage;
import org.telegram.telegrambots.meta.api.objects.Document;
import org.telegram.telegrambots.meta.api.objects.InputFile;
import org.telegram.telegrambots.meta.api.objects.Message;
import org.telegram.telegrambots.meta.api.objects.Update;
import org.telegram.telegrambots.meta.exceptions.TelegramApiException;
import org.telegram.telegrambots.updatesreceivers.DefaultBotSession;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;


public class Main extends TelegramLongPollingBot {
    public String result;
    public String format;
    public ArrayList<String> array = new ArrayList<>();
    public File checkOnVirusFile;
    public String greetings = "Привіт! Цей бот вміє перевіряти файли, посилання (URL), ip адреси на наявність вірусів або зловмисних дій. Надішліть файл, скопійоване посилання(http/https) або ip address.\n\n"+
            "Формати виведення результатів перевірки:\n\n" +
            "Для файлів: 1) Хеш MD5 2) Посилання на веб-ресурс з результатами 3) Дата сканування за UTC 4) Хеш SHA256 5) Виявлені загрози: 6) Всього перевірок: + Результати перевірок антивірусами, які виявили загрози.\n\n" +
            "Для посилань: 1)Посилання на веб-ресурс з результатами 2)Дата сканування за UTC 3) Виявлені загрози: 4) Всього перевірок: + Результати перевірок на зловмисні дії сайту, які виявили загрози.\n\n" +
            "Для ip адрес: Вам надсилається текстовий файл з результатами загроз для клжного URL за цією IP-адресою, а також доменами, що знаходяться під цією IP-адресою.";

    public File ipFile = new File("C:\\Users\\maksi\\Desktop\\VT\\src\\main\\resources\\IpReport.txt");

    public static void main(String[] args) throws TelegramApiException {
        Main bot = new Main();
        TelegramBotsApi telegramBotsApi = new TelegramBotsApi(DefaultBotSession.class);
        telegramBotsApi.registerBot(bot);
    }
public void scanFile(File file) throws InterruptedException {
    String resource;
    try {
        VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(getVTApiKey());
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

        ScanInfo scanInformation = virusTotalRef.scanFile(file);

        System.out.println("___SCAN INFORMATION___");
        System.out.println("MD5 :\t" + scanInformation.getMd5());
        System.out.println("Perma Link :\t" + scanInformation.getPermalink());
        System.out.println("Resource :\t" + scanInformation.getResource());
        System.out.println("Scan Date :\t" + scanInformation.getScanDate());
        System.out.println("Scan Id :\t" + scanInformation.getScanId());
        System.out.println("SHA1 :\t" + scanInformation.getSha1());
        System.out.println("SHA256 :\t" + scanInformation.getSha256());
        System.out.println("Verbose Msg :\t" + scanInformation.getVerboseMessage());
        System.out.println("Response Code :\t" + scanInformation.getResponseCode());
        System.out.println("done.");
        resource = scanInformation.getResource();
        Thread.sleep(300000);
        getScanReport(resource);
    } catch (APIKeyNotFoundException ex) {
        System.err.println("API Key not found! " + ex.getMessage());
    } catch (UnsupportedEncodingException ex) {
        System.err.println("Unsupported Encoding Format!" + ex.getMessage());
    } catch (UnauthorizedAccessException ex) {
        System.err.println("Invalid API Key " + ex.getMessage());
    } catch (Exception ex) {
        System.err.println("Something Bad Happened! " + ex.getMessage());
    }

}
public void getScanReport(String resource){
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(getVTApiKey());
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            FileScanReport report = virusTotalRef.getScanReport(resource);

            result = "1)MD5 хеш :\t" + report.getMd5();
            result += "\n2)Посилання на детальні результати VirusTotal :\t" + report.getPermalink();
            result += "\n3)Дата сканування :\t" + report.getScanDate();
            result += "\n4)SHA256 :\t" + report.getSha256();
            System.out.println("\n5)Verbose Msg :\t" + report.getVerboseMessage());
            result += "\n5)Виявлені загрози :\t" + report.getPositives();
            result += "\n6)Всього перевірок :\t" + report.getTotal();
            array.add(result);

            HashMap<String, VirusScanInfo> scans = report.getScans();
            for (String key : scans.keySet()) {
                VirusScanInfo virusInfo = scans.get(key);
                if(!(String.valueOf(virusInfo.getResult())).equals("null")) {
                    result = "\nАнтивірус : " + key;
                    result += "\nРезультат : " + virusInfo.getResult();
                    array.add(result);
                }
            }

        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }
    public void scanUrl(String str) throws InterruptedException{
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(getVTApiKey());
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();
            String urls[] = str.split(" ");

            ScanInfo[] scanInfoArr = virusTotalRef.scanUrls(urls);

            for (ScanInfo scanInformation : scanInfoArr) {
                System.out.println("___SCAN INFORMATION___");
                System.out.println("MD5 :\t" + scanInformation.getMd5());
                System.out.println("Perma Link :\t" + scanInformation.getPermalink());
                System.out.println("Resource :\t" + scanInformation.getResource());
                System.out.println("Scan Date :\t" + scanInformation.getScanDate());
                System.out.println("Scan Id :\t" + scanInformation.getScanId());
                System.out.println("SHA1 :\t" + scanInformation.getSha1());
                System.out.println("SHA256 :\t" + scanInformation.getSha256());
                System.out.println("Verbose Msg :\t" + scanInformation.getVerboseMessage());
                System.out.println("Response Code :\t" + scanInformation.getResponseCode());
                System.out.println("done.");
            }
            Thread.sleep(30000);
            getUrlScanReport(urls);
        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }
    public void getUrlScanReport(String [] urls) {
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(getVTApiKey());
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            FileScanReport[] reports = virusTotalRef.getUrlScanReport(urls, false);

            for (FileScanReport report : reports) {
                if (report.getResponseCode() == 0) {
                    continue;
                }
                result = "\nПосилання на детальні результати VirusTotal :\t" + report.getPermalink();
                result += "\nДата сканування :\t" + report.getScanDate();
                System.out.println("\nVerbose Msg :\t" + report.getVerboseMessage());
                result += "\nВиявлені загрози :\t" + report.getPositives();
                result += "\nВсього перевірок :\t" + report.getTotal();
                array.add(result);

                HashMap<String, VirusScanInfo> scans = report.getScans();
                for (String key : scans.keySet()) {
                    VirusScanInfo virusInfo = scans.get(key);
                    if (!(String.valueOf(virusInfo.getResult())).equals("clean site") && !(String.valueOf(virusInfo.getResult())).equals("unrated site")&& !(String.valueOf(virusInfo.getResult())).equals("spam site")&& !(String.valueOf(virusInfo.getResult())).equals("suspicious site")) {
                        result = "\nСканер : " + key;
                        result += "\nРезультат : " + virusInfo.getResult();
                        array.add(result);
                    }
                }
            }
        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }
    public void getIpReport(String str){
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(getVTApiKey());
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            IPAddressReport report = virusTotalRef.getIPAddresReport(str);

            result = "___IP Report__";
            array.add(result);

            URL[] urls = report.getDetectedUrls();
            if (urls != null) {
                result += "\nDetected URLs";
                for (URL url : urls) {
                    if (url.getPositives() > 0) {
                        result += "\nURL : " + url.getUrl();
                        result += "\nPositives : " + url.getPositives();
                        result += "\nTotal : " + url.getTotal();
                        array.add(result);
                    }
                }
            }

            IPAddressResolution[] resolutions = report.getResolutions();
            if (resolutions != null) {
                result += "\nResolutions";
                for (IPAddressResolution resolution : resolutions) {
                    result += "\nHost Name : " + resolution.getHostName();
                    result += "\nLast Resolved : " + resolution.getLastResolved();
                    array.add(result);
                }
            }

            result += "\nResponse Code : " + report.getResponseCode();
            result += "\nVerbose Message : " + report.getVerboseMessage();



        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }

        try(FileWriter fw = new FileWriter(ipFile.getAbsolutePath());
            BufferedWriter bw = new BufferedWriter(fw)){
            bw.write(result);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    public String getVTApiKey() {
        return "2ca40b2bc9f45c2faf4e30276559362899a4578f9c5bedf221657001a51f6431";
    }

    @Override
    public String getBotUsername() {
        return "@diploma_bachelor_bot";
    }

    @Override
    public String getBotToken() {
        return "5278978706:AAGHCZCSsLFwKE-DJ9lmi6yk3mUUHOg7LO4";
    }

    public void downloadFile(Document document) throws IOException, TelegramApiException {
        org.telegram.telegrambots.meta.api.objects.File file = getFilePath(document);

        int index = file.getFilePath().lastIndexOf(".");
        format = file.getFilePath().substring(index);
        checkOnVirusFile = new File("C:\\Users\\maksi\\Desktop\\VT\\src\\main\\resources\\CheckOnVirusFile" + format);
        InputStream is = new java.net.URL(file.getFileUrl(getBotToken())).openStream();
        FileUtils.copyInputStreamToFile(is, checkOnVirusFile);
    }

    public org.telegram.telegrambots.meta.api.objects.File getFilePath(Document document) throws TelegramApiException {
        GetFile getFile = new GetFile();
        getFile.setFileId(document.getFileId());
        org.telegram.telegrambots.meta.api.objects.File file = execute(getFile);
        return file;
    }

    @Override
    public void onUpdateReceived(Update update) {
        if (update.hasMessage()) {
            Message message = update.getMessage();
            if(message.hasEntities() && message.getText().equals("/start")){
                try {
                    execute(SendMessage.builder().chatId(message.getChatId().toString()).text(greetings).build());
                } catch (TelegramApiException e) {
                    throw new RuntimeException(e);
                }
            }
            else if(message.hasDocument()) {
                Document document = message.getDocument();
                try {
                    execute(SendMessage.builder().
                            chatId(message.getChatId().toString()).
                            text("Інформація оброблюється на сервері. Зачекайте 5 хвилин...").
                            build());
                } catch (TelegramApiException e) {
                    throw new RuntimeException(e);
                }
                    try {
                        downloadFile(document);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    } catch (TelegramApiException e) {
                        throw new RuntimeException(e);
                    }
                    try {
                        scanFile(checkOnVirusFile);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }
                    for (int i = 0; i < array.size(); i++) {
                        try {
                            execute(SendMessage.builder().
                                    chatId(message.getChatId().toString()).
                                    text(array.get(i)).
                                    build());
                        } catch (TelegramApiException e) {
                            throw new RuntimeException(e);
                        }
                    }
                    array.clear();
                }

            else if(message.getText().startsWith("http")) {
                try {
                    execute(SendMessage.builder().
                            chatId(message.getChatId().toString()).
                            text("Інформація оброблюється на сервері. Зачекайте 30 секунд...").
                            build());
                } catch (TelegramApiException e) {
                    throw new RuntimeException(e);
                }
                try {
                    scanUrl(message.getText());
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                for(int i = 0; i < array.size(); i++) {
                    try {
                        execute(SendMessage.builder().
                                chatId(message.getChatId().toString()).
                                text(array.get(i)).
                                build());
                    } catch (TelegramApiException e) {
                        throw new RuntimeException(e);
                    }
                }
                array.clear();
            }
            else if (message.getText().matches("\\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.|$)){4}\\b")) {
                getIpReport(message.getText());
                try {
                    execute(SendDocument.builder().chatId(message.getChatId().toString()).document(new InputFile(ipFile)).build());
                } catch (TelegramApiException e) {
                    throw new RuntimeException(e);
                }
                array.clear();
            }
            else {
                try {
                    execute(SendMessage.builder().
                            chatId(message.getChatId().toString()).
                            text("Ви вказали щось невірно, перечитайте можливості даного боту за допомогою команди /start і спробуйте знову").
                            build());
                } catch (TelegramApiException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }
}


